// SPDX-License-Identifier: GPL-2.0
/*
 * npu.c - openedges npu driver
 *
 * Copyright (C) 2020 Openedges
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <linux/device.h>
#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/delay.h>
#include <asm/cacheflush.h>

#include "npu.h"
#include "../memory/eyenix/eyenix-cmm.h"

static dev_t stDev;
struct class *stClass;

struct npu_device_data {
	struct cdev cdev;
	struct device *dev;
	
	wait_queue_head_t irq_waitq;
	atomic_t irq_done;
	
	void __iomem *membase;
	const struct npu_reg_ops *reg_ops;
	struct eyenix_cmm_item 	*cmd_buf;
	struct eyenix_cmm_item 	*in_buf;
	struct eyenix_cmm_item 	*wei_buf;
	struct eyenix_cmm_item 	*ac_buf;
	struct eyenix_cmm_item 	*out_buf;
	
	unsigned int irq;
};

struct npu_device_data devs[NPU_MAX_MINORS];

struct npu_reg_ops {
	u32 (*in)(void __iomem *addr);
	void (*out)(u32 val, void __iomem *addr);
};

static u32 npu_inbe32(void __iomem *addr)
{
	return ioread32be(addr);
}

static void npu_outbe32(u32 val, void __iomem *addr)
{
	iowrite32be(val, addr);
}

static const struct npu_reg_ops npu_be = {
	.in = npu_inbe32,
	.out = npu_outbe32,
};

static u32 npu_inle32(void __iomem *addr)
{
	return ioread32(addr);
}

static void npu_outle32(u32 val, void __iomem *addr)
{
	iowrite32(val, addr);
}

static const struct npu_reg_ops npu_le = {
	.in = npu_inle32,
	.out = npu_outle32,
};

static inline u32 npu_in32(u32 offset, struct npu_device_data *ndata)
{
	return ndata->reg_ops->in(ndata->membase + offset);
}

static inline void npu_out32(u32 val, u32 offset,
		struct npu_device_data *ndata)
{
	ndata->reg_ops->out(val, ndata->membase + offset);
}

static void npu_exit(void)
{
	unregister_chrdev_region(stDev, 1);
	cdev_del(&devs[0].cdev);
	device_destroy(stClass, devs[0].cdev.dev);
	class_destroy(stClass);

};

static irqreturn_t npu_isr(int irq, void *dev_id)
{
	struct npu_device_data *ndata = (struct npu_device_data *)dev_id;
	int int_reason, reason_clear, trap_id;

	int_reason = npu_in32(ADDR_NPU_IRQ_REASON, ndata) & 0xFF;
	trap_id = (int_reason >> 24) & 0xFF;

	if (int_reason) {
		reason_clear = NPU_IRQ_TRAP;
		npu_out32(reason_clear, (ADDR_NPU_IRQ_REASON), ndata);
		npu_out32(1, ADDR_NPU_IRQ_CLEAR, ndata);
	}
	atomic_set(&ndata->irq_done, 1);
	wake_up_interruptible(&ndata->irq_waitq);

	return IRQ_HANDLED;
}

struct npu_device_data *npu_devdata(struct file *file)
{
	return &devs[iminor(file_inode(file))];
}

void npu_core_reset(struct npu_device_data *ndata)
{
	unsigned int data;
	unsigned int int_reason, dbg_data, trap_id;

	npu_out32(NPU_CTRL_CMD_SRC | NPU_CTRL_RESET, ADDR_NPU_CONTROL, ndata);
	npu_out32(NPU_CTRL_CMD_SRC | NPU_CTRL_RESET, ADDR_NPU_CONTROL, ndata);

	npu_out32(NPU_CTRL_RESET, ADDR_NPU_CONTROL, ndata);

	dbg_data = npu_in32(ADDR_NPU_IRQ_REASON, ndata);
	int_reason = dbg_data & 0xFF;
	trap_id = (dbg_data >> 24) & 0xFF;

	npu_out32(NPU_IRQ_ALL, ADDR_NPU_IRQ_REASON, ndata);
	npu_out32(NPU_IRQ_ALL, ADDR_NPU_IRQ_CLEAR, ndata);

	data = NPU_IRQ_TRAP;

	npu_out32(data, ADDR_NPU_IRQ_MASK, ndata);
	npu_out32(data, ADDR_NPU_IRQ_ENABLE, ndata);
}

void npu_prepare_cmd(struct npu_device_data *ndata)
{
	unsigned int data;
	
	npu_core_reset(ndata);
	data =  0x000 << 20;	//R_CB   0/128
	data += 0x080 << 10;	//R_Y  128/128
	data += 0x0c5 << 0;		//R_CR 197/128
	npu_out32(data, ADDR_NPU_COLOR_CONV_0, ndata);

	data =  0x3e9 << 20;	//G_CB -23/128
	data += 0x080 << 10;	//G_Ya 128/128
	data += 0x3c5 << 0;	 //G_CR -59/128
	npu_out32(data, ADDR_NPU_COLOR_CONV_1, ndata);

	data =  0x0e8 << 20;	//B_CBa 232/128
	data += 0x080 << 10;	//B_Y   128/128
	data += 0x000 << 0;	 //B_CR    0/128
	npu_out32(data, ADDR_NPU_COLOR_CONV_2, ndata);

	data =  0x2bb << 20;	//R_BIAS - 128 : -325
	data += 0x3d2 << 10;	//G_BIAS - 128 :  -46
	data += 0x298 << 0;	 //B_BIAS - 128 : -360
	npu_out32(data, ADDR_NPU_COLOR_CONV_BIAS, ndata);

	npu_out32(ndata->cmd_buf->phys_start, ADDR_NPU_BASE_ADDR0, ndata);
	npu_out32(ndata->wei_buf->phys_start, ADDR_NPU_BASE_ADDR1, ndata);
	npu_out32(ndata->ac_buf->phys_start, ADDR_NPU_BASE_ADDR2, ndata);
	npu_out32(ndata->in_buf->phys_start, ADDR_NPU_BASE_ADDR3, ndata);
	npu_out32(ndata->out_buf->phys_start, ADDR_NPU_BASE_ADDR4, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR5, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR6, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR7, ndata);
}

ssize_t npu_in_buf_write(struct file *fp, const char *buf,
						size_t count, loff_t *ppos)
{
	struct npu_device_data *npu_data = fp->private_data;
	int ret = 0;

	ret = copy_from_user(npu_data->in_buf, buf, count);
	if (ret < 0) {
		dev_err(npu_data->dev, "Copy write buf failed\n");
		return ret;
	}

	return count;
}

ssize_t npu_out_buf_read(struct file *fp, char *buf, size_t count, loff_t *ppos)
{
	struct npu_device_data *npu_data = fp->private_data;
	int ret = 0;

	ret = copy_to_user(buf, npu_data->out_buf, count);
	if (ret) {
		dev_err(npu_data->dev, "READ Error\n");
		return ret;
	}
	flush_dcache_page(virt_to_page(npu_data->out_buf));
	return count;
}

int npu_release(struct inode *inode_p, struct file *fp)
{

	//struct npu_device_data *npu_data = fp->private_data;
	   /* to do */
	pr_info("npu devier release\n");

	return 0;
}

int npu_busy_wait(struct npu_device_data *npu, int timeout)
{
	int ms = timeout < 0 ? NPU_BUSY_WAIT_DEF_TIMEOUT : timeout;
	unsigned long end = jiffies + msecs_to_jiffies(ms);
	int data;

	do {
		data = npu_in32(ADDR_NPU_STATUS, npu);
		if (!(data & 1 << 8))
			return 0;
		usleep_range(100, 250);
	} while (ms > 0 && time_is_after_jiffies(end));

	return -EBUSY;
}

int npu_wait_interrupt(struct npu_device_data *npu, u8 irq_mask, u32 timeout)
{
	int ret = wait_event_interruptible_timeout(npu->irq_waitq,
			atomic_add_unless(&npu->irq_done, -1, 0),
			msecs_to_jiffies(timeout));
	if (ret <= 0)
		return ret ? ret : -ETIMEDOUT;

	return npu_busy_wait(npu, 1000);
}

long npu_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct npu_device_data *npu_data = fp->private_data;
	unsigned int data;
	//struct npu_buf_info npu_buf;
	//void __user *compat_arg = (void __user *)arg;
	int size, ret;

	
	if (_IOC_TYPE(cmd) != NPU_IOCTL_MAGIC) {
		dev_err(npu_data->dev, "magic code error %c vs %c\n",
					_IOC_TYPE(cmd), NPU_IOCTL_MAGIC);
		return -EINVAL;
	}
	if (_IOC_NR(cmd) >= NPU_IOCTL_MAX) {
		dev_err(npu_data->dev, "cmd num error\n");
		return -EINVAL;
	}
	size = _IOC_SIZE(cmd);
	if (size) {
		if (_IOC_DIR(cmd) & _IOC_READ) {
			if (access_ok(VERIFY_WRITE, (void *)arg, size) < 0) {
				dev_err(npu_data->dev, "read access error\n");
			return -EINVAL;
			}
		}
		if (_IOC_DIR(cmd) & _IOC_WRITE) {
			if (access_ok(VERIFY_READ, (void *)arg, size) < 0) {
				dev_err(npu_data->dev, "write access error\n");
			return -EINVAL;
			}
		}
	}

	switch	(cmd) {
		case NPU_IOCTL_RUN:
			npu_prepare_cmd(npu_data);
			// APB command for load_description
			npu_out32((NPU_OPCODE_WR_REG << 28) + (0 << 24) + ((4 - 1) << 16) + ((0x004) << 0),	ADDR_NPU_APB_COMMAND, npu_data);
			// [TODO]
			data = 0;
			npu_out32(data, ADDR_NPU_APB_COMMAND, npu_data);
			// [31:29] : reserved
			// [28:16] : ibuf_addr
			// [15:14] : ibuf_bank
			// [13   ] : csc_on
			// [12:11] : reserved
			// [10: 8] : base_buf_idx
			// [ 7: 6] : reserved
			// [ 5: 4] : mode
			// [ 3   ] : reserved
			// [ 2: 0] : cmd
			data = (0 << 8) + NPU_DMA_LOAD_DESC;
			npu_out32(data, ADDR_NPU_APB_COMMAND, npu_data);
			// offset_jump
			npu_out32(0x0, ADDR_NPU_APB_COMMAND, npu_data);
			// [31:20] num_chunk_m1
			// [19   ] reserved
			// [18: 0] sz_chunk
			npu_out32(128*4, ADDR_NPU_APB_COMMAND, npu_data);
			npu_out32((NPU_OPCODE_RUN << 28) + (1 << 24) + (1 << 16) + (0x000 << 0),
					ADDR_NPU_APB_COMMAND, (npu_data));

			npu_out32(NPU_CTRL_RUN | NPU_CTRL_CMD_SRC, ADDR_NPU_CONTROL,
								npu_data);
			ret = npu_wait_interrupt(npu_data, 0, 100);
			if (ret) {
				dev_err(npu_data->dev, "NPU Run fail\n");
				npu_core_reset(npu_data);
				return ret;
			}
		break;
	}

	return 0;
}

int npu_open(struct inode *inode, struct file *fp)
{
	struct npu_device_data *npu_data = &devs[0];

	npu_data->reg_ops = &npu_le;

	npu_core_reset(npu_data);

	/* validate access to device */
	fp->private_data = npu_data;

	return 0;
}

int npu_mmap(struct file *fp, struct vm_area_struct *vma)
{
	struct npu_device_data *npu_data = fp->private_data;
	ssize_t memlen =  vma->vm_end - vma->vm_start;
	u64 memaddr = 0;

	switch (vma->vm_pgoff)
	{
		case NPU_CMD_BUF:
			if(npu_data->cmd_buf == NULL)
				npu_data->cmd_buf = ecmm_alloc("cmd", memlen);
			memaddr = npu_data->cmd_buf->phys_start;
		break;

		case NPU_WEIGHT_BUF:
			if(npu_data->wei_buf == NULL)
				npu_data->wei_buf = ecmm_alloc("weight", memlen);
			memaddr = npu_data->wei_buf->phys_start; 
		break;

		case NPU_INPUT_BUF:
			if(npu_data->in_buf == NULL)
				npu_data->in_buf = ecmm_alloc("in", memlen);
			memaddr = npu_data->in_buf->phys_start;; 
		break;

		case NPU_OUT_BUF:
			if(npu_data->out_buf == NULL)
				npu_data->out_buf = ecmm_alloc("out", memlen);
			memaddr = npu_data->out_buf->phys_start;; 
		break;

		case NPU_ACT_BUF:
			if(npu_data->ac_buf == NULL)
				npu_data->ac_buf = ecmm_alloc("act", memlen);
			memaddr = npu_data->ac_buf->phys_start;; 
		break;

	}
	return remap_pfn_range(vma, vma->vm_start, PFN_DOWN(memaddr), memlen, vma->vm_page_prot);
}

static const struct file_operations fops = {
	.owner	 = THIS_MODULE,
	.open	 = npu_open,
	.unlocked_ioctl	 = npu_ioctl,
	.release = npu_release,
	.mmap	= npu_mmap,
};


static int npu_device_probe(struct platform_device *pdev)
{
	struct device *dev;
	struct npu_device_data *device = &devs[0];
	struct device_node *node;
	int ret = 0;

	dev = &pdev->dev;
	node = dev->of_node;

	if (!device) {
		dev_err(dev, "fail in devm_kzalloc\n");
		ret = -ENOMEM;
		return ret;
	}

	device->dev = dev;
	device->membase = of_iomap(node, 0);
	if (!device->membase)
		return -EINVAL;

	device->irq = platform_get_irq(pdev, 0);

	ret = request_irq(device->irq, npu_isr, IRQF_TRIGGER_RISING,
			"npu", device);
	if (ret) {
		dev_err(dev, "request irq fail\n");
		goto cdev_err;
	}

	init_waitqueue_head(&device->irq_waitq);

	dev_set_drvdata(dev, device);

	/*
	 * Create Device node
	 */

	ret = alloc_chrdev_region(&stDev, 0, 1, DEVICE_NAME);
	if (ret < 0) {
		dev_err(dev, "npu device init fail\n");
		goto cdev_err;
	}
	pr_info("npu device init success\n");

	stClass = class_create(THIS_MODULE, DEVICE_NAME);
	cdev_init(&devs[0].cdev, &fops);

	ret = cdev_add(&devs[0].cdev, stDev, 1);

	if (ret < 0) {
		dev_err(dev, "NPU Device driver add fail\n");
		goto cdev_err;
	}
	device_create(stClass, NULL, stDev, NULL, DEVICE_NAME);

	return 0;

cdev_err:
	free_irq(device->irq, device);
	
	return -EINVAL;
}

static int npu_device_remove(struct platform_device *pdev)
{
	struct device *dev;
	struct npu_device_data *device;

	BUG_ON(!pdev);

	dev = &pdev->dev;
	device = dev_get_drvdata(dev);

	iounmap(device->membase);
	device->membase = NULL;

	ecmm_free(device->in_buf);
	ecmm_free(device->out_buf);
	ecmm_free(device->wei_buf);
	ecmm_free(device->cmd_buf);
	ecmm_free(device->ac_buf);

	of_reserved_mem_device_release(&pdev->dev);

	free_irq(device->irq, device);

	return 0;
}


#ifdef CONFIG_OF
static const struct of_device_id npu_match[] = {
	{
		.compatible = "openedges,npu"
	},
	{}
};
MODULE_DEVICE_TABLE(of, npu_match);
#endif

static struct platform_driver npu_driver = {
	.probe	= npu_device_probe,
	.remove = npu_device_remove,
	.driver = {
		.name	= "openedges-npu",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(npu_match),
	},
};

static int __init npu_init(void)
{
	int ret = platform_driver_register(&npu_driver);

	if (ret) {
		pr_err("error(%d) in platform_driver_register\n", ret);
		return -EINVAL;
	}

	return 0;
}

module_init(npu_init);
module_exit(npu_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("OPENEDGES");
MODULE_DESCRIPTION("NPU Driver");

