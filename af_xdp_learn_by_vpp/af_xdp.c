#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <bpf/libbpf.h>

#include "af_xdp.h"

static struct list_head xsk_umem_head;
static struct list_head xsk_socket_head;
static struct list_head rxqs_head;
static struct list_head txqs_head;

static uint64_t xsk_alloc_umem_frame(af_xdp_device_t *ad)
{
	uint64_t frame;
	if (ad->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = ad->umem_frame_addr[--ad->umem_frame_free];
	ad->umem_frame_addr[ad->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(af_xdp_device_t *ad, uint64_t frame)
{
	assert(ad->umem_frame_free < NUM_FRAMES);

	ad->umem_frame_addr[ad->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(af_xdp_device_t *ad)
{
	return ad->umem_frame_free;
}

static int
af_xdp_load_program (af_xdp_create_if_args_t * args, af_xdp_device_t * ad)
{
    int fd;

    ad->linux_ifindex = if_nametoindex (ad->linux_ifname);
    if (!ad->linux_ifindex)
    {
        printf ("if_nametoindex(%s) failed\n", ad->linux_ifname);
        goto err0;
    }

    if (bpf_prog_load (args->prog, BPF_PROG_TYPE_XDP, &ad->bpf_obj, &fd))
    {
        printf (0, "bpf_prog_load(%s) failed\n", args->prog);
        goto err0;
    }

    if (bpf_set_link_xdp_fd (ad->linux_ifindex, fd, 0))
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
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    af_xdp_rxq_t *rxqs;
    af_xdp_txq_t *txqs;
    int i;

    list_for_each_entry(umem, xsk_umem_head, list) 
    {
        xsk_socket__delete (umem);
        free(umem);
    }

    list_for_each_entry(xsk, xsk_socket_head, list)
    {
        xsk_socket__delete (xsk);
        free(umem);
    }  

    list_for_each_entry(rxqs, rxqs_head, list)
        free(rxqs);
    
    list_for_each_entry(txqs, txqs_head, list)
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
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    af_xdp_rxq_t *rxq;
    af_xdp_txq_t *txq;
    struct xsk_umem_config umem_config;
    struct xsk_socket_config sock_config;
    struct xdp_options opt;
    socklen_t optlen;
    const int is_rx = qid < ad->rxq_num;
    const int is_tx = qid < ad->txq_num;
    int ret;

    umem = (struct xsk_umem *)malloc(sizeof(struct xsk_umem));
    xsk = (struct xsk_socket *)malloc(sizeof(struct xsk_socket));
    rxq = (af_xdp_rxq_t *)malloc(sizeof(af_xdp_rxq_t));
    txq = (af_xdp_txq_t *)malloc(sizeof(af_xdp_txq_t));
    if (!umem || !xsk || !rxq || !txq)
    {
        printf("malloc error\n");
        return -1;
    }

    list_add_tail(&ad->umem->list, &xsk_umem_head);
    list_add_tail(&ad->xsk->list, &xsk_socket_head);
    list_add_tail(&ad->rxqs->list, &rxqs_head);
    list_add_tail(&ad->txqs->list, &txqs_head);

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
    umem_config.fill_size = args->rxq_size;
    umem_config.comp_size = args->txq_size;
    umem_config.frame_size = 0;
    umem_config.frame_headroom = 0;
    umem_config.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
    ret = xsk_umem__create(&umem, ad->packet_buffer, ad->packet_buffer_size, fq, cq, &umem_config);
    if (ret) 
    {
        printf("xsk_umem__create failed\n");
		goto err1;
	}

    memset (&sock_config, 0, sizeof (sock_config));
    sock_config.rx_size = args->rxq_size;
    sock_config.tx_size = args->txq_size;
    sock_config.bind_flags = XDP_USE_NEED_WAKEUP;
    sock_config.xdp_flags = 
    switch (args->mode)
    {
        case AF_XDP_MODE_AUTO:
            break;
        case AF_XDP_MODE_COPY:
            sock_config.bind_flags |= XDP_COPY;
            break;
        case AF_XDP_MODE_ZERO_COPY:
            sock_config.bind_flags |= XDP_ZEROCOPY;
        break;
    }

    ret = xsk_socket__create(&xsk, ad->linux_ifname, qid, umem, rx, tx, &sock_config)
    if (ret)
    {
        printf("xsk_socket__create failed\n");
        goto err2;
    }

    fd = xsk_socket__fd (*xsk);
    optlen = sizeof (opt);
    if (getsockopt (fd, SOL_XDP, XDP_OPTIONS, &opt, &optlen))
    {
        printf ("getsockopt(XDP_OPTIONS) failed");
        goto error_exit;
    }
    if (opt.flags & XDP_OPTIONS_ZEROCOPY)
        ad->flags |= AF_XDP_DEVICE_F_ZEROCOPY;

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

    return 0;

err2:
  xsk_socket__delete (xsk);
err1:
  xsk_umem__delete (umem);

error_exit:
    free(umem);
    free(xsk);
    free(rxq);
    free(txq);
    return -ret;
}

af_xdp_device_t* af_xdp_create_if(af_xdp_create_if_args_t *args)
{
    int rxq_size = 512;
    int txq_size = 512;
    int rxq_num , txq_num, q_num;
    int i = 0;

    if (!ifname)
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
        goto err;

    q_num = clib_max (rxq_num, txq_num);
    ad->rxq_num = rxq_num;
    ad->txq_num = txq_num;

    INIT_LIST_HEAD(&xsk_umem_head);
    INIT_LIST_HEAD(&xsk_socket_head);
    INIT_LIST_HEAD(&rxqs_head);
    INIT_LIST_HEAD(&txqs_head);

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
    af_xdp_delete_if (ad);
    return NULL;
}



int main(int argc, char *argv[])
{
    
    return 0;
}