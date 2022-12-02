#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
//#include <bpf/libbpf.h>

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>

#include "thpool.h"
#include "af_xdp.h"

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define FD_NUM 8

static struct list_head xsk_umem_head;
static struct list_head xsk_socket_head;
static struct list_head rxqs_head;
static struct list_head txqs_head;

static uint64_t xsk_alloc_umem_frame(af_xdp_rxq_t *umem_t)
{
	uint64_t frame;
	if (umem_t->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = umem_t->umem_frame_addr[--umem_t->umem_frame_free];
	umem_t->umem_frame_addr[umem_t->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(af_xdp_rxq_t *umem_t, uint64_t frame)
{
	assert(umem_t->umem_frame_free < NUM_FRAMES);

	umem_t->umem_frame_addr[umem_t->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(af_xdp_rxq_t *umem_t)
{
	return umem_t->umem_frame_free;
}

static int
af_xdp_load_program (af_xdp_create_if_args_t * args, af_xdp_device_t * ad)
{
    int fd;
    struct bpf_map *map;

    ad->linux_ifindex = if_nametoindex (ad->linux_ifname);
    if (!ad->linux_ifindex)
    {
        printf ("if_nametoindex(%s) failed\n", ad->linux_ifname);
        goto err0;
    }

    if (bpf_prog_load (args->prog, BPF_PROG_TYPE_XDP, &ad->bpf_obj, &fd))
    {
        printf ("bpf_prog_load(%s) failed\n", args->prog);
        goto err0;
    }

    map = bpf_object__find_map_by_name(obj, "xsks_map");
	if (!map) {
		printf("Failed to find xsks_map in %s\n", args->prog);
		return err1;
	}

    if (bpf_set_link_xdp_fd (ad->linux_ifindex, fd, XDP_FLAGS_UPDATE_IF_NOEXIST))
    {
        printf ("bpf_set_link_xdp_fd(%s) failed\n", ad->linux_ifname);
        goto err1;
    }

    return 0;

err1:
    bpf_object__unload (ad->bpf_obj);
    ad->bpf_obj = 0;
err0:
    ad->linux_ifindex = ~0;
    return -1;
}

void af_xdp_get_q_count (const char *ifname, int *rxq_num, int *txq_num)
{
    struct ethtool_channels ec = { .cmd = ETHTOOL_GCHANNELS };
    struct ifreq ifr = { .ifr_data = (void *) &ec };
    int fd, err;

    *rxq_num = *txq_num = 1;

    fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    return;

    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", ifname);
    err = ioctl (fd, SIOCETHTOOL, &ifr);

    close (fd);

    if (err)
    return;

    *rxq_num = clib_max (ec.combined_count, ec.rx_count);
    *txq_num = clib_max (ec.combined_count, ec.tx_count);
}

void af_xdp_delete_if (af_xdp_device_t * ad)
{
    xsk_socket_t *xsk;
    xsk_umem_t *umem;
    af_xdp_rxq_t *rxqs;
    af_xdp_txq_t *txqs;

    list_for_each_entry(umem, &xsk_umem_head, list) 
    {
        xsk_umem__delete (umem->umem);
        //free(umem->umem);
    }

    list_for_each_entry(xsk, &xsk_socket_head, list)
    {
        xsk_socket__delete (xsk->xsk);
        //free(xsk->xsk);
    }  

    list_for_each_entry(rxqs, &rxqs_head, list)
        free(rxqs);
    
    list_for_each_entry(txqs, &txqs_head, list)
        free(txqs);

    if (ad->bpf_obj)
    {
        bpf_set_link_xdp_fd (ad->linux_ifindex, -1, 0);
        bpf_object__unload (ad->bpf_obj);
    }

    free(ad);
}

int af_xdp_create_queue (af_xdp_create_if_args_t *args, af_xdp_device_t *ad, int qid)
{
    xsk_umem_t *umem_t;
    xsk_socket_t *xsk_t;
    af_xdp_rxq_t *rxq;
    af_xdp_txq_t *txq;
    struct xsk_umem_config umem_config;
    struct xsk_socket_config sock_config;
    struct xdp_options opt;
    socklen_t optlen;
    const int is_rx = qid < ad->rxq_num;
    const int is_tx = qid < ad->txq_num;
    int ret, i;
    uint32_t prog_id = 0;
    uint32_t idx;

    umem_t = (xsk_umem_t *) malloc(sizeof(*umem_t));
    xsk_t = (xsk_socket_t *) malloc(sizeof(*xsk_t));
    rxq = (af_xdp_rxq_t *)malloc(sizeof(af_xdp_rxq_t));
    txq = (af_xdp_txq_t *)malloc(sizeof(af_xdp_txq_t));
    if (!umem_t || !xsk_t || !rxq || !txq)
    {
        printf("malloc error\n");
        return -1;
    }

    list_add_tail(&umem_t->list, &xsk_umem_head);
    list_add_tail(&xsk_t->list, &xsk_socket_head);
    list_add_tail(&rxq->list, &rxqs_head);
    list_add_tail(&txq->list, &txqs_head);

    umem_t->queue_index = qid;
    xsk_t->queue_index = qid;
    rxq->queue_index = qid;
    txq->queue_index = qid;

    /*
    * fq and cq must always be allocated even if unused
    * whereas rx and tx indicates whether we want rxq, txq, or both
    */
    struct xsk_ring_cons *rx = is_rx ? &rxq->rx : 0;
    struct xsk_ring_prod *fq = &rxq->fq;
    struct xsk_ring_prod *tx = is_tx ? &txq->tx : 0;
    struct xsk_ring_cons *cq = &txq->cq;
    int fd;

    rxq->mode = AF_XDP_RXQ_MODE_POLLING;

    memset (&umem_config, 0, sizeof (umem_config));
    umem_config.fill_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    umem_config.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    umem_config.frame_size = 2048;
    umem_config.frame_headroom = 0;
    //umem_config.flags = 0;
    ret = xsk_umem__create(&umem_t->umem, ad->packet_buffer, ad->packet_buffer_size, fq, cq, &umem_config);
    if (ret) 
    {
        printf("xsk_umem__create failed, ret = %d\n", ret);
		goto err1;
	}

    memset (&sock_config, 0, sizeof (sock_config));
    sock_config.rx_size = args->rxq_size;
    sock_config.tx_size = args->txq_size;
    sock_config.libbpf_flags = 0;
    sock_config.bind_flags = XDP_USE_NEED_WAKEUP;
    sock_config.bind_flags &= XDP_ZEROCOPY;
    sock_config.bind_flags |= XDP_COPY;
    sock_config.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
    sock_config.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    //sock_config.xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */

    // switch (args->mode)
    // {
    //     case AF_XDP_MODE_AUTO:
    //         break;
    //     case AF_XDP_MODE_COPY:
    //         sock_config.bind_flags |= XDP_COPY;
    //         break;
    //     case AF_XDP_MODE_ZERO_COPY:
    //         sock_config.bind_flags |= XDP_ZEROCOPY;
    //     break;
    // }

    printf("ad->linux_ifname = %s\n", ad->linux_ifname);
    ret = xsk_socket__create(&xsk_t->xsk, ad->linux_ifname, qid , umem_t->umem, rx, tx, &sock_config);
    if (ret)
    {
        printf("xsk_socket__create failed, ret = %d\n", ret);
        goto err2;
    }

    fd = xsk_socket__fd (xsk_t->xsk);
    // optlen = sizeof (opt);
    // if (getsockopt (fd, SOL_XDP, XDP_OPTIONS, &opt, &optlen))
    // {
    //     printf ("getsockopt(XDP_OPTIONS) failed");
    //     goto error_exit;
    // }
    // if (opt.flags & XDP_OPTIONS_ZEROCOPY)
    //     ad->flags |= AF_XDP_DEVICE_F_ZEROCOPY;

    ret = bpf_get_link_xdp_id(ad->linux_ifindex, &prog_id, sock_config.xdp_flags);
	if (ret)
    {
        printf ("bpf_get_link_xdp_id failed");
        goto error_exit;
    }

    rxq->xsk_fd = is_rx ? fd : -1;
    if (is_tx)
    {
        txq->xsk_fd = fd;
        /*
        spin_lock
        */
    }
    else
    {
        txq->xsk_fd = -1;
    }

    for (i = 0; i < NUM_FRAMES; i++)
		rxq->umem_frame_addr[i] = i * FRAME_SIZE;
    rxq->umem_frame_free = NUM_FRAMES;

    ret = xsk_ring_prod__reserve(&rxq->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    {
		*xsk_ring_prod__fill_addr(&rxq->fq, idx++) = xsk_alloc_umem_frame(rxq);
    }

    xsk_ring_prod__submit(&rxq->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return 0;

err2:
  xsk_socket__delete (xsk_t->xsk);
err1:
  xsk_umem__delete (umem_t->umem);

error_exit:
    //free(umem_t);
    //free(xsk_t);
    free(rxq);
    free(txq);
    return -ret;
}

af_xdp_device_t* af_xdp_create_if(af_xdp_create_if_args_t *args)
{
    int rxq_num , txq_num, q_num;
    int i = 0;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};

    if (!args->linux_ifname)
    {
        printf("ifname is NULL\n");
        return NULL;
    }
    
    af_xdp_get_q_count (args->linux_ifname, &rxq_num, &txq_num);
    /*
    Todo: rxq_num和txq_num判断
    */

    af_xdp_device_t* ad = (af_xdp_device_t*)malloc(sizeof(af_xdp_device_t));
    memset(ad, 0, sizeof(af_xdp_device_t));

    ad->linux_ifname = args->linux_ifname;
    //code: 判断ifname长度

    if (args->prog && af_xdp_load_program (args, ad))
    {
        printf("af_xdp_load_program failed\n");
        goto err;
    }

    q_num = clib_max (rxq_num, txq_num);
    ad->rxq_num = rxq_num;
    ad->txq_num = txq_num;

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

    ad->packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&ad->packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   ad->packet_buffer_size)) 
    {
		fprintf(stderr, "ERROR: Can't allocate buffer memory\n");
		exit(EXIT_FAILURE);
	}

    INIT_LIST_HEAD(&xsk_umem_head);
    INIT_LIST_HEAD(&xsk_socket_head);
    INIT_LIST_HEAD(&rxqs_head);
    INIT_LIST_HEAD(&txqs_head);

    printf("q_num = %d\n", q_num);
    for (i = 0; i < q_num; i++)
    {
        if (af_xdp_create_queue (args, ad, i))
        {
            printf("af_xdp_create_queue failed\n");
            goto err;
        }
    }

    return ad;
err:
    //af_xdp_delete_if (ad);
    return NULL;
}

static bool global_exit;

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

static void complete_tx(af_xdp_rxq_t *rxq, af_xdp_txq_t *txq)
{
    unsigned int completed;
	uint32_t idx_cq;

    sendto(txq->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&txq->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

    if (completed > 0) {
	    for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(rxq,
					    *xsk_ring_cons__comp_addr(&txq->cq,
								      idx_cq++));

		xsk_ring_cons__release(&txq->cq, completed);
		// xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
		// 	completed : xsk->outstanding_tx;
	}
}

static bool process_packet(af_xdp_txq_t *txq, uint64_t addr, uint32_t len)
{
    int ret;
	uint32_t tx_idx = 0;

    ret = xsk_ring_prod__reserve(&txq->tx, 1, &tx_idx);
    if (ret != 1) {
    /* No more transmit slots, drop the packet */
        return false;
    }

    xsk_ring_prod__tx_desc(&txq->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&txq->tx, tx_idx)->len = len;
	xsk_ring_prod__submit(&txq->tx, 1);
    return true;
}

void handle_receive_packets(void *arg)
{
    thread_args *th_args = (thread_args *)arg;
    af_xdp_device_t *ad = (af_xdp_device_t *)th_args->arg1;
    int fd = (int)th_args->arg2;

    unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

    af_xdp_rxq_t *rxq;
    af_xdp_txq_t *txq;

    list_for_each_entry(rxq, &rxqs_head, list) 
    {
        if (fd == rxq->xsk_fd)
            break;
    }

    if (rxq == NULL)
    {
        printf("rxq is NULL\n");
        return ;
    }

    list_for_each_entry(txq, &txqs_head, list) 
    {
        if (fd == rxq->xsk_fd)
            break;
    }

    if (txq == NULL)
    {
        printf("txq is NULL\n");
        return ;
    }

    rcvd = xsk_ring_cons__peek(&rxq->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

    printf("xsk_umem_free_frames(rxq) = %d\n", xsk_umem_free_frames(rxq));
    stock_frames = xsk_prod_nb_free(&rxq->fq, xsk_umem_free_frames(rxq));

    if (stock_frames > 0)
    {
        ret = xsk_ring_prod__reserve(&rxq->fq, stock_frames, &idx_fq);

        /* This should not happen, but just in case */
        while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&rxq->fq, rcvd, &idx_fq);

        for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&rxq->fq, idx_fq++) =
				xsk_alloc_umem_frame(rxq);

        xsk_ring_prod__submit(&rxq->fq, stock_frames);
    }

    /* Process received packets */
    for (i = 0; i < rcvd; i++)
    {
        uint64_t addr = xsk_ring_cons__rx_desc(&rxq->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&rxq->rx, idx_rx++)->len;

        if (!process_packet(txq, addr, len))
			xsk_free_umem_frame(rxq, addr);
    }

    xsk_ring_cons__release(&rxq->rx, rcvd);

    complete_tx(rxq, txq);
}

void rx_and_process(af_xdp_device_t * ad)
{
    struct pollfd fds[FD_NUM];
    af_xdp_rxq_t *rxq;
    threadpool thpool;
    thread_args args;
    int i = 0;
    int ret;
    int nfds = 0;

    memset(fds, 0, sizeof(fds));

    list_for_each_entry(rxq, &rxqs_head, list)
    {
        fds[i].fd = rxq->xsk_fd;
        fds[i].events = POLLIN;
        if (nfds < fds[i].fd) nfds = fds[i].fd;
        i++;
    }

    thpool = thpool_init(ad->rxq_num, "af-xdp");
    if (thpool == NULL)
    {
        printf("thpool_init failed\n");
        return ;
    }

    /* poll mode */
    while(!global_exit) 
    {
		ret = poll(fds, nfds + 1, -1);
		if (ret <= 0 )
			continue;

        for (i = 0; i < nfds; i++)
        {
            args.arg1 = (void*)ad;
            args.arg2 = (void*)fds[i].fd;
            thpool_add_work(thpool, handle_receive_packets, &args);
        } 
	}
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("./af_xdp <ifname> [bpf prog]\n");
        return 0;
    }

    signal(SIGINT, exit_application);

    af_xdp_device_t *ad;
    af_xdp_create_if_args_t args;

    args.linux_ifname = argv[1];
    if (argc >= 2)
        args.prog = argv[2];
    
    args.rxq_size = 512;
    args.txq_size = 512;

    ad =  af_xdp_create_if(&args);
    if (ad == NULL)
    {
        printf("af_xdp_create_if failed\n");
        return 0;
    }

    rx_and_process(ad);
    
    free(ad);

    //xdp_link_detach(ad->linux_ifindex, ad->flags, 0);
    return 0;
}