/*
 * openedges npu driver
 *
 * Copyright (C) 2020 Openedges
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _NPU_H
#define _NPU_H

#include <linux/ioctl.h>

#define DEVICE_NAME "npu"
#define NPU_MAJOR	   42
#define NPU_MAX_MINORS  1
#define NPU_BUSY_WAIT_DEF_TIMEOUT	250

#define NPU_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define NPU_MAX(a, b) (((a) > (b)) ? (a) : (b))

#define NPU_REGION					(6 * 16)
#define ADDR_NPU_CONTROL			0x00
#define ADDR_NPU_STATUS				0x04
#define ADDR_NPU_APB_COMMAND			0x08
#define ADDR_NPU_RESERVED0			0x0C

#define ADDR_NPU_IRQ_REASON			0x10
#define ADDR_NPU_IRQ_ENABLE			0x14
#define ADDR_NPU_IRQ_MASK			0x18
#define ADDR_NPU_IRQ_CLEAR			0x1C

#define ADDR_NPU_COLOR_CONV_0			0x20
#define ADDR_NPU_COLOR_CONV_1			0x24
#define ADDR_NPU_COLOR_CONV_2			0x28
#define ADDR_NPU_COLOR_CONV_BIAS		0x2C

#define ADDR_NPU_READ_INT_REG			0x30
#define ADDR_NPU_INT_REG_RDATA			0x34
#define ADDR_NPU_CMD_CNT			0x38

#define ADDR_NPU_BASE_ADDR0			0x40
#define ADDR_NPU_BASE_ADDR1			0x44
#define ADDR_NPU_BASE_ADDR2			0x48
#define ADDR_NPU_BASE_ADDR3			0x4C

#define ADDR_NPU_BASE_ADDR4			0x50
#define ADDR_NPU_BASE_ADDR5			0x54
#define ADDR_NPU_BASE_ADDR6			0x58
#define ADDR_NPU_BASE_ADDR7			0x5C

#define ADDR_NPU_PERF_DMA			0x60
#define ADDR_NPU_PERF_OACT			0x64

#define FEED_CMD_FULL				(32)

#define NPU_CMD_BUF 0
#define NPU_WEIGHT_BUF 1
#define NPU_INPUT_BUF 2
#define NPU_OUT_BUF 3
#define NPU_ACT_BUF 4

enum {
	NPU_CTRL_RUN		= 0x1,
	NPU_CTRL_RESET		= 0x2,
	NPU_CTRL_CMD_SRC	= 0x4,
};

enum {
	NPU_IRQ_FULL_EMPTY	= 0x1,
	NPU_IRQ_HALF_EMPTY	= 0x2,
	NPU_IRQ_TRAP		= 0x4,
	NPU_IRQ_ALL		= 0x7,
};

enum {
	NPU_OPCODE_NOP	  = 0x0,
	NPU_OPCODE_RUN	  = 0x1,
	NPU_OPCODE_WR_REG   = 0x2,
	NPU_OPCODE_TRAP	 = 0x3,
};

enum {
	NPU_WAIT_COND_DMA   = 0x1,
	NPU_WAIT_COND_COMP  = 0x2,
};

enum {
	NPU_DMA_LOAD_W	  = 0x0,
	NPU_DMA_LOAD_A	  = 0x2,
	NPU_DMA_SAVE_A	  = 0x3,
	NPU_DMA_LOAD_DESC   = 0x4,
};

//  Internal APB address map
//  |addr[10:8] : master |
//  | 0		 : DMA	|
//  | 1		 : MM	 |
//  | 2		 : DW	 |
//  | 3		 : MISC   |
//  | 4		 : ACT	|

#define ADDR_NPU_INT_APB_DMA	(0x000)
#define SIZE_NPU_INT_APB_DMA	(5)
#define ADDR_NPU_INT_APB_MM	 (0x100)
#define SIZE_NPU_INT_APB_MM	 (5)
#define ADDR_NPU_INT_APB_DW	 (0x200)
#define SIZE_NPU_INT_APB_DW	 (5)
#define ADDR_NPU_INT_APB_MISC   (0x300)
#define SIZE_NPU_INT_APB_MISC   (5)
#define ADDR_NPU_INT_APB_ACT	(0x400)
#define SIZE_NPU_INT_APB_ACT	(5)
#define RDATA_NOT_READY		 (0xFFFFFFFF)
#define INVALID_ADDR_ACCESS	 (0xBAB0BAB0)

#define CMD_QUE_NUM			 (32)
#define FEED_CMD_AT_FULL_EMTPY  (32)
#define FEED_CMD_AT_HALF_EMTPY  (16)

struct npu_buf_info {
	char *buffer;
	unsigned int size;
};

#define NPU_IOCTL_MAGIC	  'k'

#define NPU_IOCTL_RUN		   _IO(NPU_IOCTL_MAGIC, 0)
#define NPU_IOCTL_SET_CMD_BUF	   _IOW(NPU_IOCTL_MAGIC, 1, struct npu_buf_info)
#define NPU_IOCTL_SET_WEIGHT_BUF	\
			_IOW(NPU_IOCTL_MAGIC, 2, struct npu_buf_info)

#define NPU_IOCTL_MAX		3

#endif /*_NPU_H */
