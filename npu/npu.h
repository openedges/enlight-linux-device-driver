

#define ENLIGHT_NPU_V2

#ifdef ENLIGHT_NPU_V2

#define NPU_REGION					(6 * 16)
#define ADDR_NPU_CONTROL			0x00
#define ADDR_NPU_STATUS				0x04
#define ADDR_NPU_APB_COMMAND		0x08
#define ADDR_NPU_ID_CODE			0x0C

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
#define ADDR_NPU_PERF_COMP			0x64
#define ADDR_NPU_PERF_AXI_CONF	    0x70

    
#define ADDR_NPU_INT_RST_CTRL       0x74

#define ADDR_NPU_PERF_CNT_MM        0x80
#define ADDR_NPU_PERF_CNT_DW        0x84
#define ADDR_NPU_PERF_CNT_MISC      0x88
#define ADDR_NPU_PERF_CNT_MLX       0x8C

#define NUM_NPU_MLX_CORE_HCI      (16)
#define ADDR_NPU_MLX_C0_HCI_00    0x100
#define ADDR_NPU_MLX_C0_HCI_04    0x104
#define ADDR_NPU_MLX_C0_HCI_08    0x108



#define PCI_DMA_NPU_CMD_BUF_ADDRESS     0x410000000
#define PCI_DMA_NPU_WEIGHT_BUF_ADDRESS  0x412000000
#define PCI_DMA_NPU_WORK_BUF_ADDRESS    0x420000000
#define PCI_DMA_NPU_INPUT_BUF_ADDRESS   0x416000000
#define PCI_DMA_NPU_OUTPUT_BUF_ADDRESS  0x418000000

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
    NPU_OPCODE_NOP      = 0x0,
    NPU_OPCODE_RUN      = 0x1,
    NPU_OPCODE_WR_REG   = 0x2,
    NPU_OPCODE_TRAP     = 0x3,
};


struct npu_buf_info {
	int in_fd;
	int out_fd;
};

struct npu_buf_req {
    int size;
    uint64_t addr;
};

struct npu_net_req {
	int cmd_size;
	int wei_size;
    int cmd_addr;
    int wei_addr;
	char *cmd_data;
	char *wei_data;
};

#define NPU_IOCTL_MAGIC	  'k'

#define NPU_IOCTL_BUFFER_CREATE		_IOW(NPU_IOCTL_MAGIC, 0, int)
#define NPU_IOCTL_NETWORK_CREATE  	_IOW(NPU_IOCTL_MAGIC, 1, struct npu_net_req)
#define NPU_IOCTL_RUN_INFERENCE		_IOW(NPU_IOCTL_MAGIC, 2, struct npu_buf_info)
#define NPU_IOCTL_LOAD_MLX_KERNEL	_IOW(NPU_IOCTL_MAGIC, 5, int)
#define NPU_IOCTL_SET_COLOR_CONV		_IOW(NPU_IOCTL_MAGIC, 6, int) 

#endif
