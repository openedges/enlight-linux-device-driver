/*
 * npu.c - openedges npu driver
 *
 * Copyright (C) 2020 Openedges
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can access it online at
 * http://www.gnu.org/licenses/gpl-2.0.html.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/cred.h>
#include <linux/pci.h>
#include <linux/delay.h>

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/version.h>

#include <linux/eventpoll.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "npu.h"

#define TIME_OUT
//#define NPU_DEBUG
#define NPU_MAX_MINORS 2

struct npu_device_data {
    void  __iomem *mem;
	struct mutex	lock;
    int irq;
    /* to do 
     * define npu device structure
     * */

};

struct npu_buffer {
	unsigned long phys_start;
    unsigned long nbytes;		// size
    struct file *file;
};

struct npu_network {
  	struct npu_device_data *npu;
    struct npu_buffer *cmd_buf;
    struct npu_buffer *wei_buf;
    wait_queue_head_t poll_waitq;
    struct file *file;
};

struct npu_cmd {
	struct npu_network *net;
	unsigned long input;
	unsigned long out;
	struct list_head list;
};

static LIST_HEAD(npu_cmd_list);

struct pci_dev *pdev = NULL;
void  __iomem *mem;

unsigned int trap_id = -1;
int npu_pic_done = 0;
int rgb_mode = 1;

struct npu_device_data devs[NPU_MAX_MINORS];

int npu_run_pic(struct npu_cmd *cmd);

void NPU_WRITE_REG(int reg, int data)
{
    iowrite32(data, mem + reg); 
}

int NPU_READ_REG(int reg)
{
    return ioread32(mem + reg); 
}

static unsigned long get_buffer_addr(int fd)
{
	struct file *file = fget(fd);
	struct npu_buffer *npu; 
	unsigned long addr;

	if (!file)
		return -0xEBADF;

	npu = file->private_data;
	addr = npu->phys_start;
	fput(file);
	return addr;
}
static void npu_reset_seq(void)
{
    NPU_WRITE_REG(ADDR_NPU_INT_RST_CTRL, 0);
    NPU_WRITE_REG(ADDR_NPU_INT_RST_CTRL, 1 << 16);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_CMD_SRC|NPU_CTRL_RESET);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_CMD_SRC|NPU_CTRL_RESET);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_RESET);
}

static void npu_reset_pic(void)
{
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_CMD_SRC|NPU_CTRL_RESET);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_CMD_SRC|NPU_CTRL_RESET);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_RESET);
}

static uint32_t mlx_validate(uint32_t core_id)
{
    int base;
    uint32_t data;
    uint32_t core_off = core_id * 0x40;
    int cnt = 20;

    base = ADDR_NPU_MLX_C0_HCI_04 + core_off;
    data = 0xED9E;
    NPU_WRITE_REG(base, data);
        
    base = ADDR_NPU_MLX_C0_HCI_00 + core_off;
    data = 1;
    NPU_WRITE_REG(base, data);

    do
    {
        data = NPU_READ_REG(base);
       
        msleep(10); 
        if(cnt-- == 0)
                break;
    } while(data & 0x10);

    base = ADDR_NPU_MLX_C0_HCI_08 + core_off;

    data = NPU_READ_REG(base);
    return data;
}

int mlx_load_kernel(void)
{
    int i;
    int core_num;
    int cnt = 10;
    unsigned int data, trap_id, reason;

    // Reset
    npu_reset_seq();

    data = NPU_READ_REG(ADDR_NPU_ID_CODE);
    core_num = ((data >> 24) & 0xf) + 1;

    // APB command for load_description
    data = (NPU_OPCODE_WR_REG << 28);
    data += (0 << 24);
    data += ((5 - 1) << 16);
    data += (0x004 << 0);
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    data = (0x0);
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    data = 0;
    data += ((1 << core_num) - 1) << 20; // core_0
    data += 7 << 8;
    data += 6 << 0;         // 2'b10 : DRAM2CMD
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    data = 0;
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    data = 0;
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    data =  0 << 20;
    data += (0x200-1) <<  0; //15 = ((4 * 128) / 32) - 1
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    data = 0;
    data += 1 << 28;    // op_code : 1
    data += 1 << 24;    // dma_flag: 1
    data += 1 << 21;    // dma_id  : 1
    data += 1 << 16;    // wdata   : 1
    data += 0 <<  0;    // iaddr   : 13'h0000
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, 0x00200000);
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, 0x30010001);

    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_RUN);

#if 1
    do {
        data = NPU_READ_REG(ADDR_NPU_STATUS);
        data = NPU_READ_REG(ADDR_NPU_IRQ_REASON);
        reason = data & 0xFF;
        trap_id = (data >> 24) & 0xFF;

        if ((reason == NPU_IRQ_TRAP)) {
            NPU_WRITE_REG(ADDR_NPU_IRQ_REASON, NPU_IRQ_TRAP);
            NPU_WRITE_REG(ADDR_NPU_IRQ_CLEAR, 1);
            break;
        }

        msleep(10);
    } while(cnt--);

    // Run MLX Cores
    NPU_WRITE_REG(ADDR_NPU_INT_RST_CTRL, 0xf00);
    msleep(10);
    NPU_WRITE_REG(ADDR_NPU_INT_RST_CTRL, 0xf0f);

    // Validate Cores
    for (i = 0; i < core_num; i++)
    {
        msleep(10);    
        data = mlx_validate(i);
        if (data != 0x107E)
        {
            printk("MLX core %d is not validated.\r\n", i);
            return -1;
        }
        msleep(10);
    }
    #endif
    printk("All %d MLX core(s) is(are) validated.\r\n", core_num);
    return 0;
}

int npu_run_pic(struct npu_cmd *cmd);
static void npu_work_func (struct work_struct *work)
{
	struct npu_cmd *cmd, *tmp;

	list_for_each_entry_safe(cmd, tmp, &npu_cmd_list, list) {
		
		struct npu_network *net = cmd->net;
		struct npu_device_data *npu = net->npu;

        mutex_lock(&npu->lock);

		npu_run_pic(cmd);
        mutex_unlock(&npu->lock);
		list_del(&cmd->list);
		kfree(cmd);
	}
}
DECLARE_WORK(npu_work, npu_work_func );

static void init_npu(int rgb_mode)
{
    int data; 

    data = NPU_IRQ_TRAP; 

    NPU_WRITE_REG(ADDR_NPU_IRQ_MASK, data);
    NPU_WRITE_REG(ADDR_NPU_IRQ_ENABLE, data);

    if (rgb_mode) {
        data =  0x080 << 20;    //R    128/128
        data += 0x000 << 10;    //       0/128
        data += 0x000 << 0;     //       0/128
    }
    else {
        data =  0x000 << 20;    //R_CB   0/128
        data += 0x080 << 10;    //R_Y  128/128
        data += 0x0c5 << 0;     //R_CR 197/128
    }
    NPU_WRITE_REG(ADDR_NPU_COLOR_CONV_0, data);

    if (rgb_mode) {
        data =  0x000 << 20;    //       0/128
        data += 0x080 << 10;    //G    128/128
        data += 0x000 << 0;     //       0/128
    }
    else {
        data =  0x3e9 << 20;    //G_CB -23/128
        data += 0x080 << 10;    //G_Ya 128/128
        data += 0x3c5 << 0;     //G_CR -59/128
    }
    NPU_WRITE_REG(ADDR_NPU_COLOR_CONV_1, data);

    if (rgb_mode) {
        data =  0x000 << 20;    //        0/128
        data += 0x000 << 10;    //        0/128
        data += 0x080 << 0;     //B     128/128
    }
    else {
        data =  0x0e8 << 20;    //B_CB  232/128
        data += 0x080 << 10;    //B_Y   128/128
        data += 0x000 << 0;     //B_CR    0/128
    }
    NPU_WRITE_REG(ADDR_NPU_COLOR_CONV_2, data);

    if (rgb_mode) {
        data =  0x380 << 20;    //R_BIAS - 128
        data += 0x380 << 10;    //G_BIAS - 128
        data += 0x380 << 0;     //B_BIAS - 128
    }
    else {
        data =  0x2bb << 20;    //R_BIAS - 128 : -325
        data += 0x3d2 << 10;    //G_BIAS - 128 :  -46
        data += 0x298 << 0;     //B_BIAS - 128 : -360
    }
    NPU_WRITE_REG(ADDR_NPU_COLOR_CONV_BIAS, data);
}

static int npu_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int npu_release(struct inode *inode, struct file *file)
{
    return 0;
}

static int npu_net_release(struct inode *const inode,
				 struct file *const file)
{
	struct npu_network *net = file->private_data;

	fput(file);

	kfree(net);

	return 0;
}

static unsigned int npu_poll(struct file *file,
			poll_table *wait)
{
   	struct npu_network *net = file->private_data;
    int ret;
  	
    poll_wait(file, &net->poll_waitq, wait);

    ret = EPOLLIN;

    return ret;
}
long npu_net_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
        const void __user *udata = (void __user *)arg;
		struct npu_network *net = fp->private_data;
        struct npu_buf_info npu_buf;
        struct npu_device_data *npu_data = &devs[0];
        int ret;

	    switch	(cmd) {
	    case NPU_IOCTL_RUN_INFERENCE:
            {

                struct npu_cmd *cmd = kmalloc(sizeof(struct npu_cmd),GFP_KERNEL);

                mutex_lock(&npu_data->lock);

               	ret =copy_from_user(&npu_buf, udata, sizeof(npu_buf));

                cmd->net = net;
                cmd->input = get_buffer_addr(npu_buf.in_fd);
                cmd->out = get_buffer_addr(npu_buf.out_fd);
                list_add_tail(&cmd->list, &npu_cmd_list);
	
        		schedule_work(&npu_work);

               	mutex_unlock(&npu_data->lock);
                ret = 0;

            }
            break;
        case NPU_IOCTL_SET_COLOR_CONV:
            {
                rgb_mode = (int)arg;
                if (rgb_mode > 1) {
                       printk("Error, Not Support NPU Color Conversion\n");
                       ret = -1;
                        break;
                }
                printk("RGB MODE : %d\n", rgb_mode);
                init_npu(rgb_mode);
            }
            break;
        }
        return ret;
}
static const struct file_operations npu_net_fops = {
	.release = &npu_net_release,
	.unlocked_ioctl	 = &npu_net_ioctl,
	.poll = &npu_poll,
};

static int npu_buffer_mmap(struct file *file,
			      struct vm_area_struct *vma)
{
    /*
     * To-do  memory map User space
     */
    return 0;
}
static int npu_buffer_release(struct inode *const inode,
				 struct file *const file)
{
	struct npu_buffer *npu = file->private_data;
	fput(file);
	kfree(npu);

	return 0;
}

static const struct file_operations npu_buffer_fops = {
	.release = &npu_buffer_release,
	.mmap	 = &npu_buffer_mmap,
};


static int npu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct npu_device_data *npu_data = &devs[0];
    const void __user *udata = (void __user *)arg;
    int ret;

	switch	(cmd) {

	case NPU_IOCTL_NETWORK_CREATE:
		{

           	struct npu_net_req net_req;
			struct npu_network *net;

			copy_from_user(&net_req, udata, sizeof(net_req));

            net = kzalloc(sizeof(struct npu_network), GFP_KERNEL);

            net->cmd_buf = kzalloc(sizeof(struct npu_buffer), GFP_KERNEL);
            net->wei_buf = kzalloc(sizeof(struct npu_buffer), GFP_KERNEL);

#if 0
            net->cmd_buf->phys_start = PCI_DMA_NPU_CMD_BUF_ADDRESS;
            net->wei_buf->phys_start = PCI_DMA_NPU_WEIGHT_BUF_ADDRESS;
#else
            net->cmd_buf->phys_start = net_req.cmd_addr;
            net->wei_buf->phys_start = net_req.wei_addr;
#endif
            net->npu = npu_data;
            init_waitqueue_head(&net->poll_waitq);
          	ret = anon_inode_getfd("npu_network",
				       &npu_net_fops,
				       net,
				       O_ACCMODE | O_CLOEXEC);

			net->file = fget(ret);
			net->file->f_mode |= FMODE_LSEEK | FMODE_WRITE | FMODE_READ;

    		fput(net->file);
		}
	break;

	case NPU_IOCTL_BUFFER_CREATE:
		{
			struct npu_buffer *buf;
           	struct npu_buf_req buf_req;
    		int size;
			copy_from_user(&buf_req, udata, sizeof(buf_req));

			size = buf_req.size;
           
			buf = kzalloc(sizeof(struct npu_buffer), GFP_KERNEL);
			if(buf == NULL) {
				return -EFAULT;
            }

            buf->phys_start = buf_req.addr;
            buf->nbytes = buf_req.size;

			ret = anon_inode_getfd("npu-buffer",
				       &npu_buffer_fops,
				       buf,
				       O_ACCMODE | O_CLOEXEC);

			buf->file = fget(ret);
			buf->file->f_mode |= FMODE_LSEEK | FMODE_WRITE | FMODE_READ;

			fput(buf->file);
			return ret;

		}
    break;    

#if 1
	case NPU_IOCTL_LOAD_MLX_KERNEL:
        {
            printk("MLX _KERNEL\n");
            ret = mlx_load_kernel();
            return ret;
        }

	break;
#endif

	}
    return ret;
}

static ssize_t npu_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
    return 0;
}

static ssize_t npu_write(struct file *filp, const char *buff, size_t len, loff_t *off)
{
    printk (KERN_INFO "Hello Write~!!.\n");
    return -EINVAL;
}

void npu_interrupt_handler(void)
{
    unsigned int reason, data, trap_id;
    data = NPU_READ_REG(ADDR_NPU_IRQ_REASON);
    reason = data & 0xFF;
    trap_id = (data >> 24) & 0xFF;

#ifdef NPU_DEBUG
    _printf("Interrupt reason trap: %x %d\r\n", reason, trap_id);
#endif

    if (reason == NPU_IRQ_TRAP) {
        NPU_WRITE_REG(ADDR_NPU_IRQ_REASON, NPU_IRQ_TRAP);
        NPU_WRITE_REG(ADDR_NPU_IRQ_CLEAR, 1);

        if (trap_id == 0) {
            npu_pic_done = 1;
        } else {
            printk("Wrong Interrupt Trap id\n%d\n", trap_id);
            NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_RUN | NPU_CTRL_CMD_SRC);
        }
    }
    else {
        NPU_WRITE_REG(ADDR_NPU_IRQ_REASON, 0xFFFF);
        NPU_WRITE_REG(ADDR_NPU_IRQ_CLEAR, 1);
        printk("Wrong Interrupt occurs, %x\r\n", reason);
    }
}

#ifdef NPU_DEBUG
void init_cycle(void)
{
    int i;
    NPU_WRITE_REG(ADDR_NPU_CMD_CNT, 0);
    NPU_WRITE_REG(ADDR_NPU_PERF_DMA, 0);
    NPU_WRITE_REG(ADDR_NPU_PERF_COMP, 0);

    for (i = 0; i < 4; i++){
        NPU_WRITE_REG(ADDR_NPU_PERF_CNT_MM + i*0x10, 0);
        NPU_WRITE_REG(ADDR_NPU_PERF_CNT_DW + i*0x10, 0);
        NPU_WRITE_REG(ADDR_NPU_PERF_CNT_MISC + i*0x10, 0);
        NPU_WRITE_REG(ADDR_NPU_PERF_CNT_MLX + i*0x10, 0);
    }
}
void print_cycle(void)
{

    int i;

    printk(" CMD : %d, DMA : %d, COMP : %d\n",
        NPU_READ_REG(ADDR_NPU_CMD_CNT),
        NPU_READ_REG(ADDR_NPU_PERF_DMA),
        NPU_READ_REG(ADDR_NPU_PERF_COMP));

    for (i = 0; i < 4; i++){
            
    printk("Core : %d  MM : %d, Dw : %d, MISC : %d , MLX %d \n", i,
        NPU_READ_REG(ADDR_NPU_PERF_CNT_MM + i * 0x10),
        NPU_READ_REG(ADDR_NPU_PERF_CNT_DW + i * 0x10),
        NPU_READ_REG(ADDR_NPU_PERF_CNT_MISC + i * 0x10),
        NPU_READ_REG(ADDR_NPU_PERF_CNT_MLX + i * 0x10));
    }
}
#endif

void print_npu_status(void)
{
    unsigned int cmd_cnt;
    unsigned int status;
    unsigned int core3;
    unsigned int core2;
    unsigned int core1;
    unsigned int core0;
    unsigned int dma  ;
    unsigned int room ;

    cmd_cnt = NPU_READ_REG(ADDR_NPU_CMD_CNT);
    status = NPU_READ_REG(ADDR_NPU_STATUS);

    core3 = status >>28 & 0xF;
    core2 = status >>24 & 0xF;
    core1 = status >>20 & 0xF;
    core0 = status >>16 & 0xF;
    dma   = status >> 8 & 0x1;
    room  = status >> 0 & 0xFF;

    printk("NPU Status core3-0: %x:%x:%x:%x dma:%x room:%2d cmd_cnt:%8d\r\n",
            core3, core2, core1, core0, dma, room, cmd_cnt);
}

int npu_run_pic(struct npu_cmd *cmd)
{
    unsigned int data;
    int cnt = 10000;
    int ret = 0;
    struct npu_network *net = cmd->net;
        

#ifdef TIME_OUT
    int inference_time_out = 1000000*10;
    int dma_wait_time_out = 1000000*10;
#endif

#ifdef NPU_DEBUG
    init_cycle();
    print_npu_status();
#endif

    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_CMD_SRC|NPU_CTRL_RESET);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_CMD_SRC|NPU_CTRL_RESET);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_RESET);

    NPU_WRITE_REG(ADDR_NPU_IRQ_MASK, NPU_IRQ_TRAP);
    NPU_WRITE_REG(ADDR_NPU_IRQ_ENABLE, NPU_IRQ_TRAP);
    // APB command for 
    //
    //
    //
    // load_description
    data = (NPU_OPCODE_WR_REG << 28);
    data += (0 << 24);
    data += ((5 - 1) << 16);
    data += (0x004 << 0);
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    // reg1
    // [31: 0] : ext mem base
    data = (unsigned long)0;
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    // reg2
    // [23:20] : dst_core_flag   only when cmd = 2'b00, 2'b11
    // [17:16] : src_core_idx    only when cmd = 2'b01, 2'b11
    // [15:13] : reserved
    // [12   ] : input_conv_en
    // [10: 8] : base_buf_idx
    // [ 7: 6] : im2col_mode
    // [ 5: 4] : trans_mode
    // [ 3   ] : reserved
    // [ 1: 0] : cmd
    data = 0;
    data += 0 << 8;
    data += 2 << 0;         // 2'b10 : DRAM2CMD
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    // reg3
    // [30:16] : gbuf_addr_src
    // [14: 0] : gbuf_addr_dst
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, 0x0);

    // reg4
    // [20: 0] : offset_jump
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, 0x0);

    // reg5
    // [31:20] num_chunk_m1
    // [12: 0] sz_chunk
    data =  0 << 20;
    data += 15 <<  0; //15 = ((4 * 128) / 32) - 1
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);

    // reg0
    // APB command when op_code == RUN
    // [31:28] op_code
    // [27:24] reserved
    // [   24] dma_flag
    // [23:21] dma_id
    // [20:16] wdata
    // [15:13] reserved
    // [12: 0] iaddr
    data = 0;
    data += 1 << 28;    // op_code : 1
    data += 1 << 24;    // dma_flag: 1
    data += 0 << 21;    // dma_id  : 0
    data += 1 << 16;    // wdata   : 1
    data += 0 <<  0;    // iaddr   : 13'h0000
    NPU_WRITE_REG(ADDR_NPU_APB_COMMAND, data);
//net->cmd_buf->phys_start, net->wei_buf->phys_start
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR0, net->cmd_buf->phys_start);
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR1, net->wei_buf->phys_start);
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR2, (PCI_DMA_NPU_WORK_BUF_ADDRESS >> 4));
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR3, (cmd->input));
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR4, (cmd->out));
//printk(" i, o : %x %x \n", cmd->input, cmd->out);
    NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_RUN | NPU_CTRL_CMD_SRC);

    do {
        int reason, data;
        data = NPU_READ_REG(ADDR_NPU_IRQ_REASON);
        reason = data & 0xFF;
        trap_id = (data >> 24) & 0xFF;

        if (reason)
            npu_interrupt_handler();

        if ((reason == NPU_IRQ_TRAP) && (trap_id == 0)) {
            break;
        }

#ifdef TIME_OUT
        if (inference_time_out-- == 0) {
            printk("NPU timeout failed\r\n");
            NPU_WRITE_REG(ADDR_NPU_CONTROL, NPU_CTRL_CMD_SRC);

            while(NPU_READ_REG(ADDR_NPU_STATUS) & 0x100) {

                msleep(10);

                if (dma_wait_time_out-- == 0) {
                    printk("NPU DMA wait timeout failed\r\n");
                    break;
                }
            }

            npu_reset_seq();
        }
#endif

#ifdef NPU_DEBUG
        //print_npu_status();
#endif
    } while(inference_time_out);

#ifdef NPU_DEBUG
    print_cycle();
#endif

    NPU_WRITE_REG(ADDR_NPU_CONTROL, 0);
    wake_up_interruptible(&net->poll_waitq);
    if(cnt >= 0)
        ret =  0;
    else
        ret = -1;
    return ret;
}

static const struct file_operations npu_fops = \
{
    .owner = THIS_MODULE,
    .open = &npu_open,
    .read = &npu_read,
    .write = &npu_write,
    .release = &npu_release,
    .mmap = &npu_buffer_mmap,
    .unlocked_ioctl = (void*) &npu_ioctl,
    .compat_ioctl = (void*) &npu_ioctl
};

static struct miscdevice npu_device = \
{
    MISC_DYNAMIC_MINOR,
    "npu",
    &npu_fops
};

irqreturn_t test_handler(int irq, void *dev_id)
{
        return IRQ_HANDLED;
}

static int __init npu_init(void)
{
   	struct npu_device_data *device;
    unsigned long len;
	unsigned long phys;
    int retval = 0;
  
    retval = misc_register(&npu_device);

    pdev = pci_get_device(0x10ee, 0x903f, pdev);
    //configure_device(pdev);
   
    //printk(" pci e resource %d \n", pci_resource_len(pdev, 0));
    //printk(" pci e resource %d \n", pci_resource_len(pdev, 1));
    phys = pci_resource_start(pdev, 0);
    len =  pci_resource_len(pdev, 0);


    device = &devs[0];
    device->mem = pci_iomap(pdev, 0, len);
    //mem = pci_iomap(pdev, 0, len);
    mem = device->mem;
	mutex_init(&device->lock);

    npu_reset_seq();

    init_npu(rgb_mode);

    npu_reset_pic();
#if 0 
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR0, (PCI_DMA_NPU_CMD_BUF_ADDRESS >> 4));
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR1, (PCI_DMA_NPU_WEIGHT_BUF_ADDRESS >> 4));
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR2, (PCI_DMA_NPU_WORK_BUF_ADDRESS >> 4));
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR3, (PCI_DMA_NPU_INPUT_BUF_ADDRESS >> 4));
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR4, (PCI_DMA_NPU_OUTPUT_BUF_ADDRESS >> 4));
#endif
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR5,0x400000000 >> 4);
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR6,0x400000000 >> 4);
    NPU_WRITE_REG(ADDR_NPU_BASE_ADDR7,0x480000000 >> 4); /* for mlx kernel load */

    return 0;
}

static void __exit npu_exit(void)
{   
    misc_deregister(&npu_device);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OPENEDGES");
MODULE_DESCRIPTION("NPU Driver");

module_init(npu_init);
module_exit(npu_exit);
