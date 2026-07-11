/****************************************************************************
 * drivers/virtio/virtio-net.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <debug.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <nuttx/compiler.h>
#include <nuttx/kmalloc.h>
#include <nuttx/mutex.h>
#include <nuttx/semaphore.h>
#include <nuttx/net/ip.h>
#include <nuttx/net/netdev_lowerhalf.h>
#include <nuttx/virtio/virtio.h>
#include <nuttx/net/wifi_sim.h>

#include "virtio-net.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Virtio net feature bits */

#define VIRTIO_NET_F_MAC      5
#define VIRTIO_NET_F_CTRL_VQ  17
#define VIRTIO_NET_F_CTRL_RX  18

/* Virtio net control commands (class / cmd) — see VIRTIO 1.x §5.1.6.5 */

#define VIRTIO_NET_CTRL_RX          0
#define VIRTIO_NET_CTRL_RX_PROMISC  0
#define VIRTIO_NET_CTRL_RX_ALLMULTI 1

#define VIRTIO_NET_OK   0
#define VIRTIO_NET_ERR  1

/* Virtio net header size and packet buffer size */

#define VIRTIO_NET_HDRSIZE    (sizeof(struct virtio_net_hdr_s))
#define VIRTIO_NET_LLHDRSIZE  (sizeof(struct virtio_net_llhdr_s))
#define VIRTIO_NET_BUFSIZE    (CONFIG_NET_ETH_PKTSIZE + CONFIG_NET_GUARDSIZE)

/* Virtio net virtqueue index and number.
 *
 * Phase 127.B.5 — when the device exposes VIRTIO_NET_F_CTRL_VQ, the
 * driver creates a third (control) queue used to set ALLMULTI / PROMISC
 * etc. Without that, QEMU's virtio-net backend filters every incoming
 * frame whose destination MAC isn't this NIC's unicast or broadcast,
 * which silently drops RTPS SPDP frames bound for `01:00:5e:7f:00:01`
 * (mcast 239.255.0.1). The driver always tries to create three queues
 * and falls back to two if the backend masked CTRL_VQ off.
 */

#define VIRTIO_NET_RX         0
#define VIRTIO_NET_TX         1
#define VIRTIO_NET_CTRL       2
#define VIRTIO_NET_NUM        3

#define VIRTIO_NET_MAX_PKT_SIZE \
    ((CONFIG_NET_LL_GUARDSIZE - ETH_HDRLEN) + VIRTIO_NET_BUFSIZE)
#define VIRTIO_NET_MAX_NIOB \
    ((VIRTIO_NET_MAX_PKT_SIZE + CONFIG_IOB_BUFSIZE - 1) / CONFIG_IOB_BUFSIZE)

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* Virtio net header, just define it here for further, now only use it
 * to calculate the virto net header size, see marco VIRTIO_NET_HDRSIZE
 */

begin_packed_struct struct virtio_net_hdr_s
{
  uint8_t  flags;
  uint8_t  gso_type;
  uint16_t hdr_len;
  uint16_t gso_size;
  uint16_t csum_start;
  uint16_t csum_offset;
} end_packed_struct;

/* The definition of the struct virtio_net_config refers to the link
 * https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/
 * virtio-v1.2-cs01.html#x1-2230004.
 */

begin_packed_struct struct virtio_net_config_s
{
  uint8_t  mac[IFHWADDRLEN];                 /* VIRTIO_NET_F_MAC */
  uint16_t status;                           /* VIRTIO_NET_F_STATUS */
  uint16_t max_virtqueue_pairs;              /* VIRTIO_NET_F_MQ */
  uint16_t mtu;                              /* VIRTIO_NET_F_MTU */
  uint32_t speed;                            /* VIRTIO_NET_F_SPEED_DUPLEX */
  uint8_t  duplex;
  uint8_t  rss_max_key_size;                 /* VIRTIO_NET_F_RSS */
  uint16_t rss_max_indirection_table_length;
  uint32_t supported_hash_types;
} end_packed_struct;

struct virtio_net_priv_s
{
#ifdef CONFIG_DRIVERS_WIFI_SIM
  /* wifi device information, which includes the netdev lowerhalf */

  struct wifi_sim_lowerhalf_s lower;
#else

  /* This holds the information visible to the NuttX network */

  struct netdev_lowerhalf_s lower;     /* The netdev lowerhalf */
#endif

  spinlock_t                lock[VIRTIO_NET_NUM];

  /* Control-queue command state (#167). The device DMAs the ack and posts
   * the completion token ASYNCHRONOUSLY, so the R/W buffers and the sem must
   * outlive the caller's stack frame — the original stack-allocated versions
   * were reused by the returning frame before a late/duplicate completion
   * landed, smashing a saved return address (rv-virt boot panic, EPC=0x4).
   * `ctrl_lock` serializes commands so this single shared set is safe.
   */

  mutex_t                   ctrl_lock; /* Serializes control-queue commands */
  sem_t                     ctrl_sem;  /* Completion token (posted from IRQ) */
  struct
  {
    uint8_t class;
    uint8_t cmd;
  } ctrl_hdr;                          /* CTRL header (device reads) */
  uint8_t                   ctrl_data; /* CTRL payload (device reads) */
  uint8_t                   ctrl_ack;  /* CTRL ack (device writes) */

  /* Virtio device information */

  FAR struct virtio_device *vdev;      /* Virtio device pointer */
  int                       bufnum;    /* TX and RX Buffer number */
};

/* Virtio Link Layer Header, follow shows the iob buffer layout:
 *
 * |<-- CONFIG_NET_LL_GUARDSIZE -->|
 * +---------------+---------------+------------+------+     +-------------+
 * | Virtio Header |  ETH Header   |    data    | free | --> | next netpkt |
 * +---------------+---------------+------------+------+     +-------------+
 * |               |<--------- datalen -------->|
 * ^base           ^data
 *
 * CONFIG_NET_LL_GUARDSIZE >= VIRTIO_NET_LLHDRSIZE + ETH_HDR_SIZE
 *                          = sizeof(uintptr) + 10 + 14
 *                          = 32 (64-Bit)
 *                          = 28 (32-Bit)
 */

begin_packed_struct struct virtio_net_llhdr_s
{
  FAR netpkt_t           *pkt;         /* Netpaket pointer */
  struct virtio_net_hdr_s vhdr;        /* Virtio net header */
} end_packed_struct;

static_assert(CONFIG_NET_LL_GUARDSIZE >= VIRTIO_NET_LLHDRSIZE + ETH_HDRLEN,
              "CONFIG_NET_LL_GUARDSIZE cannot be less than ETH_HDRLEN"
              " + VIRTIO_NET_LLHDRSIZE");

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int virtio_net_ifup(FAR struct netdev_lowerhalf_s *dev);
static int virtio_net_ifdown(FAR struct netdev_lowerhalf_s *dev);
static int virtio_net_send(FAR struct netdev_lowerhalf_s *dev,
                           FAR netpkt_t *pkt);
static netpkt_t *virtio_net_recv(FAR struct netdev_lowerhalf_s *dev);
#ifdef CONFIG_NET_MCASTGROUP
static int virtio_net_addmac(FAR struct netdev_lowerhalf_s *dev,
                             FAR const uint8_t *mac);
static int virtio_net_rmmac(FAR struct netdev_lowerhalf_s *dev,
                            FAR const uint8_t *mac);
#endif
#ifdef CONFIG_NETDEV_IOCTL
static int virtio_net_ioctl(FAR struct netdev_lowerhalf_s *dev,
                            int cmd, unsigned long arg);
#endif
static void virtio_net_txfree(FAR struct netdev_lowerhalf_s *dev);

static int  virtio_net_probe(FAR struct virtio_device *vdev);
static void virtio_net_remove(FAR struct virtio_device *vdev);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct virtio_driver g_virtio_net_driver =
{
  LIST_INITIAL_VALUE(g_virtio_net_driver.node), /* node */
  VIRTIO_ID_NETWORK,                            /* device id */
  virtio_net_probe,                             /* probe */
  virtio_net_remove,                            /* remove */
};

static const struct netdev_ops_s g_virtio_net_ops =
{
  virtio_net_ifup,
  virtio_net_ifdown,
  virtio_net_send,
  virtio_net_recv,
#ifdef CONFIG_NET_MCASTGROUP
  virtio_net_addmac,
  virtio_net_rmmac,
#endif
#ifdef CONFIG_NETDEV_IOCTL
  virtio_net_ioctl,
#endif
  virtio_net_txfree
};

#ifdef CONFIG_DRIVERS_WIFI_SIM
static uint8_t g_netdev_num = 0;
#endif

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: virtio_net_addbuffer
 ****************************************************************************/

static int virtio_net_addbuffer(FAR struct netdev_lowerhalf_s *dev,
                                FAR struct virtqueue *vq, FAR netpkt_t *pkt,
                                unsigned int vq_id)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;
  FAR struct virtio_net_llhdr_s *hdr;
  struct virtqueue_buf vb[VIRTIO_NET_MAX_NIOB + 1];
  struct iovec iov[VIRTIO_NET_MAX_NIOB];
  int iov_cnt;
  int i;

  /* Convert netpkt to virtqueue_buf */

  iov_cnt = netpkt_to_iov(dev, pkt, iov, VIRTIO_NET_MAX_NIOB);

  /* Alloc cookie and net header from transport layer */

  hdr = (FAR struct virtio_net_llhdr_s *)
          ((FAR uint8_t *)iov[0].iov_base - VIRTIO_NET_LLHDRSIZE);
  DEBUGASSERT((FAR uint8_t *)hdr >= netpkt_getbase(pkt));
  memset(&hdr->vhdr, 0, sizeof(hdr->vhdr));
  hdr->pkt = pkt;

  /* Prepare buffers depends on the feature VIRTIO_F_ANY_LAYOUT */

  if (virtio_has_feature(priv->vdev, VIRTIO_F_ANY_LAYOUT))
    {
      /* Append the virtio net header to the first buffer */

      vb[0].buf = &hdr->vhdr;
      vb[0].len = iov[0].iov_len + VIRTIO_NET_HDRSIZE;

#if VIRTIO_NET_MAX_NIOB > 1
      for (i = 1; i < iov_cnt; i++)
        {
          vb[i].buf = iov[i].iov_base;
          vb[i].len = iov[i].iov_len;
        }
#endif
    }
  else
    {
      /* Buffer 0 is only for virtio net header */

      vb[0].buf = &hdr->vhdr;
      vb[0].len = VIRTIO_NET_HDRSIZE;

      for (i = 0; i < iov_cnt; i++)
        {
          vb[i + 1].buf = iov[i].iov_base;
          vb[i + 1].len = iov[i].iov_len;
        }

      iov_cnt++;
    }

  vrtinfo("Fill vq=%u, hdr=%p, count=%d\n", vq_id, hdr, iov_cnt);
  if (vq_id == VIRTIO_NET_RX)
    {
      return virtqueue_add_buffer_lock(vq, vb, 0, iov_cnt, hdr,
                                       &priv->lock[vq_id]);
    }
  else
    {
      return virtqueue_add_buffer_lock(vq, vb, iov_cnt, 0, hdr,
                                       &priv->lock[vq_id]);
    }
}

/****************************************************************************
 * Name: virtio_net_rxfill
 ****************************************************************************/

static void virtio_net_rxfill(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;
  FAR struct virtqueue *vq = priv->vdev->vrings_info[VIRTIO_NET_RX].vq;
  FAR netpkt_t *pkt;
  int i;

  for (i = 0; i < priv->bufnum; i++)
    {
      /* IOB Offload, Alloc buffer from RX netpkt */

      pkt = netpkt_alloc(dev, NETPKT_RX);
      if (pkt == NULL)
        {
          vrtinfo("Has ran out of the RX buffer, i=%d\n", i);
          break;
        }

      /* Preserve data length */

      if (netpkt_setdatalen(dev, pkt, VIRTIO_NET_BUFSIZE) <
          VIRTIO_NET_BUFSIZE)
        {
          vrtwarn("No enough buffer to prepare RX buffer, i=%d\n", i);
          netpkt_free(dev, pkt, NETPKT_RX);
          break;
        }

      /* Add buffer to RX virtqueue */

      virtio_net_addbuffer(dev, vq, pkt, VIRTIO_NET_RX);
    }

  if (i > 0)
    {
      virtqueue_kick_lock(vq, &priv->lock[VIRTIO_NET_RX]);
    }
}

/****************************************************************************
 * Name: virtio_net_txfree
 ****************************************************************************/

static void virtio_net_txfree(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;
  FAR struct virtqueue *vq = priv->vdev->vrings_info[VIRTIO_NET_TX].vq;
  FAR struct virtio_net_llhdr_s *hdr;

  while (1)
    {
      /* Get buffer from tx virtqueue */

      hdr = virtqueue_get_buffer_lock(vq, NULL, NULL,
                                      &priv->lock[VIRTIO_NET_TX]);
      if (hdr == NULL)
        {
          break;
        }

      netpkt_free(dev, hdr->pkt, NETPKT_TX);
      vrtinfo("Free, hdr: %p, pkt: %p\n", hdr, hdr->pkt);
    }
}

/****************************************************************************
 * Name: virtio_net_ifup
 ****************************************************************************/

static int virtio_net_ifup(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;

#ifdef CONFIG_NET_IPv4
  vrtinfo("Bringing up: %u.%u.%u.%u\n",
          ip4_addr1(dev->netdev.d_ipaddr), ip4_addr2(dev->netdev.d_ipaddr),
          ip4_addr3(dev->netdev.d_ipaddr), ip4_addr4(dev->netdev.d_ipaddr));
#endif
#ifdef CONFIG_NET_IPv6
  vrtinfo("Bringing up: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
          dev->netdev.d_ipv6addr[0], dev->netdev.d_ipv6addr[1],
          dev->netdev.d_ipv6addr[2], dev->netdev.d_ipv6addr[3],
          dev->netdev.d_ipv6addr[4], dev->netdev.d_ipv6addr[5],
          dev->netdev.d_ipv6addr[6], dev->netdev.d_ipv6addr[7]);
#endif

  /* Prepare interrupt and packets for receiving */

  virtqueue_enable_cb_lock(priv->vdev->vrings_info[VIRTIO_NET_RX].vq,
                           &priv->lock[VIRTIO_NET_RX]);
  virtio_net_rxfill(dev);

#ifdef CONFIG_DRIVERS_WIFI_SIM
  if (priv->lower.wifi == NULL)
#endif
    {
      netdev_lower_carrier_on(dev);
    }

  return OK;
}

/****************************************************************************
 * Name: virtio_net_ifdown
 ****************************************************************************/

static int virtio_net_ifdown(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;
  int i;

  /* Disable the Ethernet interrupt */

  for (i = 0; i < VIRTIO_NET_NUM; i++)
    {
      virtqueue_disable_cb_lock(priv->vdev->vrings_info[i].vq,
                                &priv->lock[i]);
    }

#ifdef CONFIG_DRIVERS_WIFI_SIM
  if (priv->lower.wifi)
    {
      return dev->iw_ops->disconnect(dev);
    }
  else
#endif
    {
      netdev_lower_carrier_off(dev);
      return OK;
    }
}

/****************************************************************************
 * Name: virtio_net_send
 ****************************************************************************/

static int virtio_net_send(FAR struct netdev_lowerhalf_s *dev,
                           FAR netpkt_t *pkt)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;
  FAR struct virtqueue *vq = priv->vdev->vrings_info[VIRTIO_NET_TX].vq;

  /* Check the send length */

  if (netpkt_getdatalen(dev, pkt) > VIRTIO_NET_BUFSIZE)
    {
      vrterr("net send buffer too large\n");
      return -EINVAL;
    }

  /* Add buffer to vq and notify the other side */

  virtio_net_addbuffer(dev, vq, pkt, VIRTIO_NET_TX);
  virtqueue_kick_lock(vq, &priv->lock[VIRTIO_NET_TX]);

  /* Try return Netpkt TX buffer to upper-half. */

  virtio_net_txfree(dev);

  /* If we have no buffer left, enable TX done callback. */

  if (netdev_lower_quota_load(dev, NETPKT_TX) <= 0)
    {
      virtqueue_enable_cb_lock(vq, &priv->lock[VIRTIO_NET_TX]);
    }

  return OK;
}

/****************************************************************************
 * Name: virtio_net_recv
 ****************************************************************************/

static netpkt_t *virtio_net_recv(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;
  FAR struct virtqueue *vq = priv->vdev->vrings_info[VIRTIO_NET_RX].vq;
  FAR struct virtio_net_llhdr_s *hdr;
  irqstate_t flags;
  uint32_t len;

  /* Fill the free Netpkt RX buffer to the RX virtqueue */

  virtio_net_rxfill(dev);

  /* Get received buffer form RX virtqueue */

  flags = spin_lock_irqsave(&priv->lock[VIRTIO_NET_RX]);
  hdr = virtqueue_get_buffer(vq, &len, NULL);
  if (hdr == NULL)
    {
      /* If we have no buffer left, enable RX callback. */

      virtqueue_enable_cb(vq);
      spin_unlock_irqrestore(&priv->lock[VIRTIO_NET_RX], flags);

      vrtinfo("get NULL buffer\n");
      return NULL;
    }
  else
    {
      spin_unlock_irqrestore(&priv->lock[VIRTIO_NET_RX], flags);
    }

  /* Set the received pkt length */

  netpkt_setdatalen(dev, hdr->pkt, len - VIRTIO_NET_HDRSIZE);
  vrtinfo("Recv, hdr=%p, pkt=%p, len=%" PRIu32 "\n", hdr, hdr->pkt, len);
  return hdr->pkt;
}

/****************************************************************************
 * Name: virtio_net_ctl_notify_cb
 *
 * Phase 127.B.5 — control-queue completion. Posts the semaphore the
 * caller is blocked on so `virtio_net_send_ctrl_rx` can return.
 ****************************************************************************/

static void virtio_net_ctl_notify_cb(FAR struct virtqueue *vq)
{
  FAR struct virtio_net_priv_s *priv = vq->vq_dev->priv;
  FAR sem_t *ctl_sem;

  ctl_sem = virtqueue_get_buffer_lock(vq, NULL, NULL,
                                      &priv->lock[VIRTIO_NET_CTRL]);
  if (ctl_sem != NULL)
    {
      nxsem_post(ctl_sem);
    }
}

/****************************************************************************
 * Name: virtio_net_send_ctrl_rx
 *
 * Phase 127.B.5 — send a single `VIRTIO_NET_CTRL_RX` class command
 * (PROMISC / ALLMULTI / etc.) with a single-byte `on` payload, block
 * until the device acks, return 0 on VIRTIO_NET_OK.
 ****************************************************************************/

static int virtio_net_send_ctrl_rx(FAR struct virtio_net_priv_s *priv,
                                   uint8_t cmd, uint8_t on)
{
  FAR struct virtqueue *vq = priv->vdev->vrings_info[VIRTIO_NET_CTRL].vq;
  struct virtqueue_buf vb[3];
  irqstate_t flags;
  int ret;

  /* #167 — serialize control commands and DMA to/from the priv-embedded
   * buffers, never the stack: the device writes `ctrl_ack` and posts the
   * completion token asynchronously, so a stack frame would be reused
   * before a late completion landed and smash a saved return address.
   */

  nxmutex_lock(&priv->ctrl_lock);

  priv->ctrl_hdr.class = VIRTIO_NET_CTRL_RX;
  priv->ctrl_hdr.cmd   = cmd;
  priv->ctrl_data      = on;
  priv->ctrl_ack       = VIRTIO_NET_ERR;

  /* Three sg slots: hdr (R) + payload (R) + ack (W). Linux's
   * virtio_net does the same split — QEMU's parser is lenient about
   * concatenation but strict about hdr being its own sg slot. `vb` may
   * stay on the stack: the device reads the copied vring descriptors, not
   * `vb` itself, and `virtqueue_add_buffer` completes the copy inline. */

  vb[0].buf = &priv->ctrl_hdr;
  vb[0].len = sizeof(priv->ctrl_hdr);
  vb[1].buf = &priv->ctrl_data;
  vb[1].len = sizeof(priv->ctrl_data);
  vb[2].buf = &priv->ctrl_ack;
  vb[2].len = sizeof(priv->ctrl_ack);

  flags = spin_lock_irqsave(&priv->lock[VIRTIO_NET_CTRL]);
  virtqueue_add_buffer(vq, vb, 2, 1, &priv->ctrl_sem);
  virtqueue_kick(vq);
  spin_unlock_irqrestore(&priv->lock[VIRTIO_NET_CTRL], flags);

  ret = nxsem_wait_uninterruptible(&priv->ctrl_sem);
  if (ret >= 0)
    {
      ret = (priv->ctrl_ack == VIRTIO_NET_OK) ? OK : -EIO;
    }

  nxmutex_unlock(&priv->ctrl_lock);
  return ret;
}

#ifdef CONFIG_NET_MCASTGROUP
/****************************************************************************
 * Name: virtio_net_addmac
 *
 * Phase 127.B.5 — IGMP joins call here when an app does
 * `IP_ADD_MEMBERSHIP`. Without CTRL_VQ negotiated, QEMU's virtio-net
 * backend filters out the matching multicast MAC. The driver leaves
 * the MAC filter table untouched (the device is held in ALLMULTI from
 * `virtio_net_init`); just return OK so the IGMP layer doesn't tear
 * down state for an addmac that succeeded at the L2 level.
 ****************************************************************************/

static int virtio_net_addmac(FAR struct netdev_lowerhalf_s *dev,
                             FAR const uint8_t *mac)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;

  if (virtio_has_feature(priv->vdev, VIRTIO_NET_F_CTRL_VQ))
    {
      /* ALLMULTI was set at probe time; new multicast MACs are already
       * delivered. Acknowledge the join silently.
       */

      return OK;
    }
  return -ENOSYS;
}

/****************************************************************************
 * Name: virtio_net_rmmac
 ****************************************************************************/

static int virtio_net_rmmac(FAR struct netdev_lowerhalf_s *dev,
                            FAR const uint8_t *mac)
{
  FAR struct virtio_net_priv_s *priv = (FAR struct virtio_net_priv_s *)dev;

  if (virtio_has_feature(priv->vdev, VIRTIO_NET_F_CTRL_VQ))
    {
      return OK;
    }
  return -ENOSYS;
}
#endif

#ifdef CONFIG_NETDEV_IOCTL
/****************************************************************************
 * Name: virtio_net_ioctl
 ****************************************************************************/

static int virtio_net_ioctl(FAR struct netdev_lowerhalf_s *dev,
                            int cmd, unsigned long arg)
{
  return -ENOTTY;
}
#endif

/****************************************************************************
 * Name: virtio_net_rxready
 ****************************************************************************/

static void virtio_net_rxready(FAR struct virtqueue *vq)
{
  FAR struct virtio_net_priv_s *priv = vq->vq_dev->priv;

  virtqueue_disable_cb_lock(vq, &priv->lock[VIRTIO_NET_RX]);
  netdev_lower_rxready((FAR struct netdev_lowerhalf_s *)priv);
}

/****************************************************************************
 * Name: virtio_net_txdone
 ****************************************************************************/

static void virtio_net_txdone(FAR struct virtqueue *vq)
{
  FAR struct virtio_net_priv_s *priv = vq->vq_dev->priv;

  virtqueue_disable_cb_lock(vq, &priv->lock[VIRTIO_NET_TX]);
  netdev_lower_txdone((FAR struct netdev_lowerhalf_s *)priv);
}

/****************************************************************************
 * Name: virtio_net_init
 ****************************************************************************/

static int virtio_net_init(FAR struct virtio_net_priv_s *priv,
                           FAR struct virtio_device *vdev)
{
  FAR const char *vqnames[VIRTIO_NET_NUM];
  vq_callback callbacks[VIRTIO_NET_NUM];
  unsigned int nvqs;
  int ret;

  spin_lock_init(&priv->lock[VIRTIO_NET_RX]);
  spin_lock_init(&priv->lock[VIRTIO_NET_TX]);
  spin_lock_init(&priv->lock[VIRTIO_NET_CTRL]);
  nxmutex_init(&priv->ctrl_lock);
  nxsem_init(&priv->ctrl_sem, 0, 0);
  priv->vdev = vdev;
  vdev->priv = priv;

  /* Initialize the virtio device.
   *
   * Phase 127.B.5 — request CTRL_VQ + CTRL_RX so we can flip the
   * device into ALLMULTI mode. QEMU's virtio-net backend exposes
   * both unconditionally, but the negotiation mask makes the
   * driver continue to work against backends that don't.
   */

  virtio_set_status(vdev, VIRTIO_CONFIG_STATUS_DRIVER);
  virtio_negotiate_features(vdev, (1UL << VIRTIO_NET_F_MAC) |
                                  (1UL << VIRTIO_F_ANY_LAYOUT) |
                                  (1UL << VIRTIO_NET_F_CTRL_VQ) |
                                  (1UL << VIRTIO_NET_F_CTRL_RX), NULL);
  virtio_set_status(vdev, VIRTIO_CONFIG_FEATURES_OK);

  vqnames[VIRTIO_NET_RX]     = "virtio_net_rx";
  vqnames[VIRTIO_NET_TX]     = "virtio_net_tx";
  vqnames[VIRTIO_NET_CTRL]   = "virtio_net_ctrl";
  callbacks[VIRTIO_NET_RX]   = virtio_net_rxready;
  callbacks[VIRTIO_NET_TX]   = virtio_net_txdone;
  callbacks[VIRTIO_NET_CTRL] = virtio_net_ctl_notify_cb;

  nvqs = virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ) ? VIRTIO_NET_NUM
                                                        : VIRTIO_NET_NUM - 1;
  ret = virtio_create_virtqueues(vdev, 0, nvqs, vqnames,
                                 callbacks, NULL);
  if (ret < 0)
    {
      vrterr("virtio_device_create_virtqueue failed, ret=%d\n", ret);
      return ret;
    }

  virtio_set_status(vdev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

  /* Phase 127.B.5 — put the device into ALLMULTI so RTPS SPDP
   * frames (`01:00:5e:7f:00:01` / `01:00:5e:7f:ff:fa`) make it
   * past the backend's MAC filter. Without this, IGMP joins at
   * the L3 level are honoured but the L2 frames never arrive.
   */

  if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_RX))
    {
      int rc = virtio_net_send_ctrl_rx(priv,
                                       VIRTIO_NET_CTRL_RX_PROMISC, 1);
      if (rc < 0)
        {
          vrtwarn("virtio_net: PROMISC=1 failed rc=%d\n", rc);
        }
      rc = virtio_net_send_ctrl_rx(priv,
                                   VIRTIO_NET_CTRL_RX_ALLMULTI, 1);
      if (rc < 0)
        {
          vrtwarn("virtio_net: ALLMULTI=1 failed rc=%d\n", rc);
        }
    }

#if CONFIG_DRIVERS_VIRTIO_NET_BUFNUM > 0
  priv->bufnum = CONFIG_DRIVERS_VIRTIO_NET_BUFNUM;
#else
  /* Calculate the virtio network buffer number:
   * 1/4 for the TX netpkts, 1/4 for the RX netpkts.
   */

  priv->bufnum = CONFIG_IOB_NBUFFERS / VIRTIO_NET_MAX_NIOB / 4;
#endif
  priv->bufnum = MIN(vdev->vrings_info[VIRTIO_NET_RX].info.num_descs /
                     (VIRTIO_NET_MAX_NIOB + 1), priv->bufnum);
  priv->bufnum = MIN(vdev->vrings_info[VIRTIO_NET_TX].info.num_descs /
                     (VIRTIO_NET_MAX_NIOB + 1), priv->bufnum);
  return OK;
}

static void virtio_net_set_macaddr(FAR struct virtio_net_priv_s *priv)
{
  FAR struct net_driver_s *dev =
                   &((FAR struct netdev_lowerhalf_s *)&priv->lower)->netdev;
  FAR struct virtio_device *vdev = priv->vdev;
  FAR uint8_t *mac = dev->d_mac.ether.ether_addr_octet;

  if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC))
    {
      virtio_read_config_bytes(vdev,
                               offsetof(struct virtio_net_config_s, mac),
                               mac, IFHWADDRLEN);
    }
  else
    {
      /* Assign a random locally-created MAC address.
       *
       * TODO:  The generated MAC address should be checked to see if it
       *        conflicts with something else on the network.
       */

      mac[0] = 0x42;
      arc4random_buf(mac + 1, 5);
    }
}

/****************************************************************************
 * Name: virtio_net_probe
 ****************************************************************************/

static int virtio_net_probe(FAR struct virtio_device *vdev)
{
  FAR struct netdev_lowerhalf_s *netdev;
  FAR struct virtio_net_priv_s *priv;
  int ret;

  priv = kmm_zalloc(sizeof(*priv));
  if (priv == NULL)
    {
      vrterr("Virtio net driver priv alloc failed\n");
      return -ENOMEM;
    }

  ret = virtio_net_init(priv, vdev);
  if (ret < 0)
    {
      vrterr("virtio_net_init failed, ret=%d\n", ret);
      goto err_with_priv;
    }

  /* Initialize the netdev lower half */

  netdev = (FAR struct netdev_lowerhalf_s *)priv;
  netdev->quota[NETPKT_RX] = priv->bufnum;
  netdev->quota[NETPKT_TX] = priv->bufnum;
  netdev->ops = &g_virtio_net_ops;

#ifdef CONFIG_DRIVERS_WIFI_SIM
  /* If the WiFi interfaces has reached the setting value,
   * no more WiFi interfaces will be created.
   */

  if (g_netdev_num < CONFIG_WIFI_SIM_NUMBER)
    {
      ret = wifi_sim_init(&priv->lower);
      if (ret < 0)
        {
          goto err_with_virtqueues;
        }
    }

#endif

  /* Register the net device */

  ret = netdev_lower_register(netdev,
#ifdef CONFIG_DRIVERS_WIFI_SIM
                              g_netdev_num++ < CONFIG_WIFI_SIM_NUMBER ?
                              NET_LL_IEEE80211 : NET_LL_ETHERNET
#else
                              NET_LL_ETHERNET
#endif
                              );
  if (ret < 0)
    {
      vrterr("netdev_lower_register failed, ret=%d\n", ret);
#ifdef CONFIG_DRIVERS_WIFI_SIM
      wifi_sim_remove(&priv->lower);
      g_netdev_num--;
#endif
      goto err_with_virtqueues;
    }

  virtio_net_set_macaddr(priv);

  return ret;

err_with_virtqueues:
  virtio_reset_device(vdev);
  virtio_delete_virtqueues(vdev);
err_with_priv:
  kmm_free(priv);
  return ret;
}

/****************************************************************************
 * Name: virtio_net_remove
 ****************************************************************************/

static void virtio_net_remove(FAR struct virtio_device *vdev)
{
  FAR struct virtio_net_priv_s *priv = vdev->priv;

  netdev_lower_unregister((FAR struct netdev_lowerhalf_s *)priv);
  virtio_reset_device(vdev);
  virtio_delete_virtqueues(vdev);
  nxmutex_destroy(&priv->ctrl_lock);
  nxsem_destroy(&priv->ctrl_sem);
#ifdef CONFIG_DRIVERS_WIFI_SIM
  g_netdev_num--;
  wifi_sim_remove(&priv->lower);
#endif
  kmm_free(priv);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: virtio_register_net_driver
 ****************************************************************************/

int virtio_register_net_driver(void)
{
  return virtio_register_driver(&g_virtio_net_driver);
}
