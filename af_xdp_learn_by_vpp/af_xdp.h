#ifndef _H_AF_XDP_
#define _H_AF_XDP_

#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include "type.h"
#include "list.h"

#define AF_XDP_NUM_RX_QUEUES_ALL        ((u16)-1)

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

typedef enum
{
    AF_XDP_RXQ_MODE_UNKNOWN,
    AF_XDP_RXQ_MODE_POLLING,
    AF_XDP_RXQ_MODE_INTERRUPT,
} __clib_packed af_xdp_rxq_mode_t;

typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

    /* fields below are accessed in data-plane (hot) */
    struct list_head list;
    //clib_spinlock_t syscall_lock;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod fq;
    int xsk_fd;
    uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

    /* fields below are accessed in control-plane only (cold) */

    u32 file_index;
    u32 queue_index;
    af_xdp_rxq_mode_t mode;
} af_xdp_rxq_t;

typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

    /* fields below are accessed in data-plane (hot) */
    struct list_head list;
    //clib_spinlock_t lock;
    //clib_spinlock_t syscall_lock;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons cq;
    int xsk_fd;

    /* fields below are accessed in control-plane only (cold) */

    u32 queue_index;
} af_xdp_txq_t;

typedef struct
{
    struct list_head list;
    struct xsk_umem *umem;
    u32 queue_index;
}xsk_umem_t;

typedef struct
{
    struct list_head list;
    struct xsk_socket *xsk;
    u32 queue_index;
}xsk_socket_t;

typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

    /* fields below are accessed in data-plane (hot) */

    af_xdp_rxq_t *rxqs;
    af_xdp_txq_t *txqs;
    //vlib_buffer_t *buffer_template;
    u32 per_interface_next_index;
    u32 sw_if_index;
    u32 hw_if_index;
    u32 flags;
    u8 pool;			/* buffer pool index */
    u8 txq_num;

    /* fields below are accessed in control-plane only (cold) */

    char *name;
    char *linux_ifname;
    u32 dev_instance;
    u8 hwaddr[6];

    u8 rxq_num;

    // struct xsk_umem **umem;
    // struct xsk_socket **xsk;
    xsk_umem_t *umem;
    xsk_socket_t *xsk;

    struct bpf_object *bpf_obj;
    unsigned int linux_ifindex;

    void *packet_buffer;
	uint64_t packet_buffer_size;

    /* error */
    //clib_error_t *error;
} af_xdp_device_t;

typedef enum
{
    AF_XDP_MODE_AUTO = 0,
    AF_XDP_MODE_COPY = 1,
    AF_XDP_MODE_ZERO_COPY = 2,
} af_xdp_mode_t;

typedef enum
{
    AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK = 1,
} af_xdp_create_flag_t;

typedef struct
{
    char *linux_ifname;
    char *name;
    char *prog;
    char *netns;
    af_xdp_mode_t mode;
    af_xdp_create_flag_t flags;
    u32 rxq_size;
    u32 txq_size;
    u32 rxq_num;

    /* return */
    int rv;
    u32 sw_if_index;
    //clib_error_t *error;
} af_xdp_create_if_args_t;

void af_xdp_get_q_count (const char *ifname, int *rxq_num, int *txq_num);
int af_xdp_create_queue (af_xdp_create_if_args_t *args, af_xdp_device_t *ad, int qid);
void af_xdp_delete_if (af_xdp_device_t * ad);
af_xdp_device_t* af_xdp_create_if(af_xdp_create_if_args_t* );

void handle_receive_packets(void *arg);
void rx_and_process(af_xdp_device_t * ad);
void af_xdp_device_input_handle();
void af_xdp_device_output_handle();


#endif