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
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/vmstat.h>
#include <linux/mmzone.h>

#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/wait.h>

#include "npu.h"
#include "../memory/eyenix/eyenix-cmm.h"

#define NET_IDLE 0
#define NET_RUN 1
#define NET_STOP 2
#define NET_DONE 3
#define NET_ERR 4
#define NET_DMA_BUSY 5

#define NPU_RUN		1
#define NPU_STOP	2

#define ENPUSTOP	(__force __poll_t)0x00010000
#define EDMABUSY	(__force __poll_t)0x00020000

static dev_t stDev;
struct class *stClass;

struct npu_device_data {
	struct cdev cdev;
	struct device *dev;
	
	wait_queue_head_t irq_waitq;
	atomic_t irq_done;
	
	void __iomem *membase;
	const struct npu_reg_ops *reg_ops;
	struct eyenix_cmm_item *work_buf;
	struct mutex	lock;
	unsigned int irq;	
	unsigned int w_fd;
	unsigned int status;
};

struct npu_network {
	struct npu_device_data *npu;
	struct eyenix_cmm_item *cmd_buf;
	struct eyenix_cmm_item *wei_buf;
	wait_queue_head_t poll_waitq;
	int status;
	struct file *file;
};

struct npu_buf {
	struct eyenix_cmm_item 	*in_buf;
	struct file *file;
};

static struct timeval pre_ts;
static struct timeval ts;
static u64 elapsed_msecs64;	

struct npu_device_data devs[NPU_MAX_MINORS];

struct npu_reg_ops {
	u32 (*in)(void __iomem *addr);
	void (*out)(u32 val, void __iomem *addr);
};

struct npu_cmd {
	int id;
	struct npu_network *net;
	unsigned long input;
	unsigned long out;
	unsigned long work;
	struct list_head list;
};
static LIST_HEAD(npu_cmd_list);

int inference_run(struct npu_cmd *cmd);
static void npu_work_func (struct work_struct *work)
{
	struct npu_cmd *cmd, *tmp;

	list_for_each_entry_safe(cmd, tmp, &npu_cmd_list, list) {
		
		struct npu_network *net = cmd->net;
		struct npu_device_data *npu = net->npu;

		if(npu->status == NPU_STOP)
			break;
	
		inference_run(cmd);
		list_del(&cmd->list);
		kfree(cmd);
	}
}

DECLARE_WORK(npu_work, npu_work_func );

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

static int npu_buffer_release(struct inode *const inode,
				 struct file *const file)
{
	struct npu_buf *npu = file->private_data;
	ecmm_free(npu->in_buf);
	fput(npu->file);
	kfree(npu);

	return 0;
}

static struct eyenix_cmm_item *npu_get_buf(int fd)
{
	struct file *file = fget(fd);
	struct npu_buf *npu = file->private_data;

	if (!file)
		return ERR_PTR(-EBADF);
	fput(file);

	return npu->in_buf;	
}
static int npu_buffer_mmap(struct file *file,
			      struct vm_area_struct *vma)
{
	struct eyenix_cmm_item 	*buf;
	struct npu_buf *npu;
	ssize_t memlen =  vma->vm_end - vma->vm_start;
	u64 memaddr = 0;

	npu = file->private_data;
	buf = npu->in_buf;
	memaddr = buf->phys_start;

	if (memaddr == NULL)
		return -EFAULT;
	return remap_pfn_range(vma, vma->vm_start, PFN_DOWN(memaddr), memlen, vma->vm_page_prot);
}

static const struct file_operations npu_buffer_fops = {
	.release = &npu_buffer_release,
	.mmap	 = &npu_buffer_mmap,
};

static int npu_net_release(struct inode *const inode,
				 struct file *const file)
{
	struct npu_network *net = file->private_data;

	if(net->cmd_buf) 
		ecmm_free(net->cmd_buf);
	
	if(net->wei_buf)
		ecmm_free(net->wei_buf);

	fput(net->file);

	kfree(net);

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

int npu_stop(struct npu_device_data *npu)
{
	int e_cnt = 0, ret = 0;

	npu_out32(NPU_CTRL_CMD_SRC, ADDR_NPU_CONTROL,npu);
	while(npu_in32(ADDR_NPU_STATUS, npu) & 0x100) {
		msleep(10);
		if(e_cnt++ >= NPU_WAIT_DMA_BUSY_CNT) {
			ret = -EBUSY;
			break;
		}
	}		
	
	npu->status = NPU_STOP;
	atomic_set(&npu->irq_done, 1);
	wake_up_interruptible(&npu->irq_waitq);

	return 0;
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

static unsigned long get_work_buffer_addr(struct npu_device_data *npu)
{
	return npu->work_buf->phys_start;
}


static unsigned long get_buffer_addr(int fd)
{
	struct file *file = fget(fd);
	struct npu_buf *npu; 
	struct eyenix_cmm_item 	*buf;
	unsigned long addr;

	if (!file)
		return ERR_PTR(-EBADF);

	npu = file->private_data;
	buf = npu->in_buf;
	addr = buf->phys_start;
	fput(file);
	return addr;
}

static void npu_core_reset(struct npu_device_data *ndata)
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

static void npu_prepare(struct npu_network *net)
{
	struct npu_device_data *ndata = net->npu;
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

	npu_out32(net->cmd_buf->phys_start, ADDR_NPU_BASE_ADDR0, ndata);
	npu_out32(net->wei_buf->phys_start, ADDR_NPU_BASE_ADDR1, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR2, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR3, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR4, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR5, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR6, ndata);
	npu_out32(0, ADDR_NPU_BASE_ADDR7, ndata);
}

int inference_run(struct npu_cmd *cmd)
{
	struct npu_network *net = cmd->net;
	struct npu_device_data *npu_data = net->npu;
	int data = 0, ret = 0, e_cnt = 0;	
	
	mutex_lock(&npu_data->lock);
	
	net->status = NET_RUN;
	npu_prepare(net);
		
	npu_out32((NPU_OPCODE_WR_REG << 28) + (0 << 24) + ((4 - 1) << 16) + ((0x004) << 0),	ADDR_NPU_APB_COMMAND, npu_data);

	npu_out32(cmd->input, ADDR_NPU_BASE_ADDR3, npu_data);
	npu_out32(cmd->out, ADDR_NPU_BASE_ADDR4, npu_data);
	npu_out32(npu_data->work_buf->phys_start, ADDR_NPU_BASE_ADDR2, npu_data);
	data = 0;
	npu_out32(data, ADDR_NPU_APB_COMMAND, npu_data);
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
	printk("run\n");
	ret = npu_wait_interrupt(npu_data, 0, 1000);
	if (ret) {
		npu_out32(NPU_CTRL_CMD_SRC, ADDR_NPU_CONTROL,npu_data);
		while(npu_in32(ADDR_NPU_STATUS, npu_data) & 0x100) {
			msleep(10);
			if(e_cnt++ >= NPU_WAIT_DMA_BUSY_CNT) {
				ret = -EBUSY;
				break;
			}
		}		
		msleep(1);
		if (npu_in32(ADDR_NPU_STATUS, npu_data) & 0x100)
			ret = -EBUSY;

		if (ret == -EBUSY)
			net->status = NET_DMA_BUSY;
		else
			net->status = NET_ERR;

		wake_up_interruptible(&net->poll_waitq);
		
		dev_err(npu_data->dev, "NPU Run fail %d\n", ret);
		mutex_unlock(&npu_data->lock);
		return ret;
	}
	if(npu_data->status == NPU_STOP) {
		net->status = NET_STOP;
		wake_up_interruptible(&net->poll_waitq);
		mutex_unlock(&npu_data->lock);
		return -EBUSY;
	} else {
		net->status = NET_DONE;
		mutex_unlock(&npu_data->lock);
		wake_up_interruptible(&net->poll_waitq);
	}
	return 0;
}


long npu_net_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	
	struct npu_network *net = fp->private_data;
	struct npu_device_data *npu_data = net->npu;
	const void __user *udata = (void __user *)arg;
	
	struct npu_buf_info npu_buf;
	unsigned int data = 0;
	unsigned int size = 0, ret = 0;
	int e_cnt =0;

	if (_IOC_TYPE(cmd) != NPU_IOCTL_MAGIC) {
		dev_err(npu_data->dev, "magic code error %c vs %c\n",
					_IOC_TYPE(cmd), NPU_IOCTL_MAGIC);
		return -EINVAL;
	}
	if (_IOC_NR(cmd) >= NPU_IOCTL_MAX) {
		dev_err(npu_data->dev, "cmd num error\n");
		return -EINVAL;
	}

	switch	(cmd) {
	case NPU_IOCTL_RUN_INFERENCE:
		{
		struct npu_cmd *cmd = kmalloc(sizeof(struct npu_cmd),GFP_KERNEL);

		if (net->status >= NET_RUN)
			return -1;
		ret =copy_from_user(&npu_buf, udata, sizeof(npu_buf));

		cmd->net = net;
		cmd->input = get_buffer_addr(npu_buf.in_fd);	
		cmd->out = get_buffer_addr(npu_buf.out_fd);	
		list_add_tail(&cmd->list, &npu_cmd_list);
	
		schedule_work(&npu_work);
		npu_data->status = NET_RUN;
		}
	break;
	}
	return 0;
}

static __poll_t npu_poll(struct file *file,
			poll_table *wait)
{
	struct npu_network *net = file->private_data;
	struct npu_device_data *npu = net->npu;

	__poll_t ret = 0;

		
	poll_wait(file, &net->poll_waitq, wait);

	do {
		ret = wait_event_interruptible_timeout(net->poll_waitq,
			net->status >= 2, msecs_to_jiffies(1000));

		msleep(1);
	} while(ret == -ERESTARTSYS);

	if (net->status == NET_DONE)
		ret = EPOLLIN;
	
	else if(net->status == NET_ERR)
		ret = EPOLLERR;

	else if(net->status == NET_STOP)
		ret = EPOLLERR;
	else if(net->status == NET_DMA_BUSY)
		ret = EDMABUSY;

	net->status = NET_IDLE;
	return ret;
}

static const struct file_operations npu_net_fops = {
	.release = &npu_net_release,
	.unlocked_ioctl	 = &npu_net_ioctl,
	.poll = npu_poll,
};



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

int npu_release(struct inode *inode_p, struct file *fp)
{

	struct npu_device_data *npu_data = fp->private_data;

	pr_info("npu driver release\n");

	return 0;
}

long npu_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct npu_device_data *npu_data = fp->private_data;
	unsigned int data;
	const void __user *udata = (void __user *)arg;
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
		case NPU_IOCTL_NETWORK_CREATE: {
			struct npu_net_req net_req;
			struct npu_network *net;

			copy_from_user(&net_req, udata, sizeof(net_req));
		
			mutex_lock(&npu_data->lock);
			printk("Npu Network create\n");	
			net = kzalloc(sizeof(struct npu_network), GFP_KERNEL);
			if (net < 0) {
				pr_err("allocation file for Network\n");
				return -EFAULT;
			}
					
			net->cmd_buf = ecmm_alloc("cmd_buf",net_req.cmd_size);
			net->wei_buf = ecmm_alloc("weigt_buf",net_req.wei_size);
			
			net->status = 0;
			init_waitqueue_head(&net->poll_waitq);
			net->npu = npu_data;

			ret = copy_from_user(page_address(net->cmd_buf->ppage), net_req.cmd_data, net_req.cmd_size);
			ret = copy_from_user(page_address(net->wei_buf->ppage), net_req.wei_data, net_req.wei_size);
		
			ret = anon_inode_getfd("npu_network",
				       &npu_net_fops,
				       net,
				       O_ACCMODE | O_CLOEXEC);

			net->file = fget(ret);
			net->file->f_mode |= FMODE_LSEEK | FMODE_WRITE | FMODE_READ;

			fput(net->file);

			mutex_unlock(&npu_data->lock);
			return ret;
		}

		break;

		case NPU_IOCTL_WORK_BUFFER_CREATE:
			size = udata;
			int cma_allow = (global_zone_page_state(NR_FREE_CMA_PAGES) << 2) * 1024;
			mutex_lock(&npu_data->lock);
			if ( npu_data->work_buf) {
				if( npu_data->work_buf->nbytes >  size)	{
					mutex_unlock(&npu_data->lock);
					return npu_data->work_buf->nbytes;
				}
				if ((npu_data->work_buf->nbytes + cma_allow) < size) {
					printk("Not allow Cma memory!\n");
					break;	
				} else {
					ecmm_free(npu_data->work_buf);
				}
					
			}	
			npu_data->work_buf = ecmm_alloc("work, buf", size);
			
			mutex_unlock(&npu_data->lock);
			return npu_data->work_buf->nbytes;
		break;

		case NPU_IOCTL_GET_WORK_BUFFER_SIZE:
			if (npu_data->work_buf)
				return npu_data->work_buf->nbytes;
			else
				-ENOMEM;
		break;

		case NPU_IOCTL_BUFFER_CREATE: 
		{
			mutex_lock(&npu_data->lock);
			struct npu_buf *buf;
			
			size = udata;
			buf = kzalloc(sizeof(struct npu_buf), GFP_KERNEL);
			buf->in_buf = ecmm_alloc("buf", size);	
			if(buf == NULL) {
				printk("CMA Alloc Fail\n");
				return -EFAULT;
			}

			ret = anon_inode_getfd("input-buffer",
				       &npu_buffer_fops,
				       buf,
				       O_ACCMODE | O_CLOEXEC);

			buf->file = fget(ret);
			buf->file->f_mode |= FMODE_LSEEK | FMODE_WRITE | FMODE_READ;

			fput(buf->file);
			mutex_unlock(&npu_data->lock);
			return ret;
		}	
		break;

		case NPU_IOCTL_STOP_NPU:
		{
			
			struct npu_cmd *cmd, *tmp;
			ret = npu_stop(npu_data);
			npu_data->status = NPU_STOP;
			list_for_each_entry_safe(cmd, tmp, &npu_cmd_list, list) {
				struct npu_network *net = cmd->net;
				struct npu_device_data *npu = net->npu;

				net->status = NET_STOP;
			}

			list_del_init(&npu_cmd_list);
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

	/* validate access to device */
	fp->private_data = npu_data;

	return 0;
}


static const struct file_operations fops = {
	.owner	 = THIS_MODULE,
	.open	 = npu_open,
	.unlocked_ioctl	 = npu_ioctl,
	.release = npu_release,
};


static int npu_device_probe(struct platform_device *pdev)
{
	struct device *dev;
	struct npu_device_data *device = &devs[0];
	struct device_node *node;
	int ret = 0;
	int size = 0;

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

	mutex_init(&device->lock);

	if(!of_property_read_u32(node, "work-buffer-size", &size))
		device->work_buf = ecmm_alloc("work_buf", size);
	else 
		printk("Not found work-buffer-size!\n");

	device->status = NPU_RUN;

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

