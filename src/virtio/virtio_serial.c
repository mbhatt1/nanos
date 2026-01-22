/*
 * VirtIO Serial/Console Driver
 *
 * Implements virtio-serial (device ID 3) for host communication.
 * Used by Authority Kernel proxy for out-of-band communication with akproxy daemon.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 */

#include <kernel.h>
#include <errno.h>
#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

/* #define VIRTIO_SERIAL_DEBUG */
#ifdef VIRTIO_SERIAL_DEBUG
#define vserial_debug(x, ...) do {tprintf(sym(vserial), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define vserial_debug(x, ...)
#endif

/* Buffer sizes */
#define VSERIAL_RX_BUFSIZE  4096
#define VSERIAL_TX_BUFSIZE  4096
#define VSERIAL_NUM_RX_BUFS 4

/* VirtIO console feature bits */
#define VIRTIO_CONSOLE_F_SIZE       0   /* Configuration has cols/rows */
#define VIRTIO_CONSOLE_F_MULTIPORT  1   /* Multiple ports supported */
#define VIRTIO_CONSOLE_F_EMERG_WRITE 2  /* Emergency write supported */

/* Receive buffer */
typedef struct vserial_rxbuf {
    void *buf;
    u64 phys;
    u64 len;                        /* Received data length */
    u64 consumed;                   /* Amount consumed by reader */
    boolean pending;                /* Waiting for completion */
    closure_struct(vqfinish, complete);
    struct vserial_rxbuf *next;
} *vserial_rxbuf;

/* Transmit buffer */
typedef struct vserial_txbuf {
    void *buf;
    u64 phys;
    u64 len;
    closure_struct(vqfinish, complete);
    struct vserial_txbuf *next;
} *vserial_txbuf;

/* Driver state */
static struct virtio_serial {
    heap general;
    backed_heap backed;
    vtdev dev;

    /* Virtqueues: 0 = receiveq, 1 = transmitq */
    virtqueue rxq;
    virtqueue txq;

    /* Receive buffers (ring buffer of completed RX) */
    struct vserial_rxbuf rxbufs[VSERIAL_NUM_RX_BUFS];
    vserial_rxbuf rx_head;          /* Next buffer to read from */
    vserial_rxbuf rx_tail;          /* Last completed buffer */
    word rx_ready_count;            /* Number of ready buffers (word for fetch_and_add) */

    /* TX free list */
    vserial_txbuf tx_free;
    struct spinlock tx_lock;

    /* State */
    boolean initialized;
    boolean connected;
} vserial;

/* Forward declarations */
static void vserial_post_rx(vserial_rxbuf rxbuf);
static vserial_txbuf vserial_alloc_txbuf(void);

/* ============================================================
 * RECEIVE PATH
 * ============================================================ */

closure_func_basic(vqfinish, void, vserial_rx_complete, u64 len)
{
    vserial_rxbuf rxbuf = struct_from_closure(vserial_rxbuf, complete);
    vserial_debug("%s: rxbuf %p, len %ld\n", func_ss, rxbuf, len);

    rxbuf->len = len;
    rxbuf->consumed = 0;
    rxbuf->pending = false;

    /* Add to ready queue */
    fetch_and_add(&vserial.rx_ready_count, 1);
}

static void vserial_post_rx(vserial_rxbuf rxbuf)
{
    vserial_debug("%s: posting rxbuf %p\n", func_ss, rxbuf);

    rxbuf->pending = true;
    rxbuf->len = 0;
    rxbuf->consumed = 0;

    vqmsg m = allocate_vqmsg(vserial.rxq);
    if (m == INVALID_ADDRESS) {
        vserial_debug("%s: failed to allocate vqmsg\n", func_ss);
        rxbuf->pending = false;
        return;
    }

    /* Host writes to this buffer */
    vqmsg_push(vserial.rxq, m, rxbuf->phys, VSERIAL_RX_BUFSIZE, true);
    vqmsg_commit(vserial.rxq, m, (vqfinish)&rxbuf->complete);
}

static void vserial_init_rx(void)
{
    vserial_debug("%s\n", func_ss);

    vserial.rx_head = &vserial.rxbufs[0];
    vserial.rx_tail = &vserial.rxbufs[0];
    vserial.rx_ready_count = 0;

    for (int i = 0; i < VSERIAL_NUM_RX_BUFS; i++) {
        vserial_rxbuf rxbuf = &vserial.rxbufs[i];
        rxbuf->buf = alloc_map(vserial.backed, VSERIAL_RX_BUFSIZE, &rxbuf->phys);
        if (rxbuf->buf == INVALID_ADDRESS) {
            msg_err("vserial: failed to allocate rx buffer %d\n", i);
            return;
        }
        init_closure_func(&rxbuf->complete, vqfinish, vserial_rx_complete);
        rxbuf->next = &vserial.rxbufs[(i + 1) % VSERIAL_NUM_RX_BUFS];
        vserial_post_rx(rxbuf);
    }
}

/* ============================================================
 * TRANSMIT PATH
 * ============================================================ */

closure_func_basic(vqfinish, void, vserial_tx_complete, u64 len)
{
    vserial_txbuf txbuf = struct_from_closure(vserial_txbuf, complete);
    vserial_debug("%s: txbuf %p, len %ld\n", func_ss, txbuf, len);
    (void)len;

    /* Return to free list */
    spin_lock(&vserial.tx_lock);
    txbuf->next = vserial.tx_free;
    vserial.tx_free = txbuf;
    spin_unlock(&vserial.tx_lock);
}

static vserial_txbuf vserial_alloc_txbuf(void)
{
    spin_lock(&vserial.tx_lock);
    vserial_txbuf txbuf = vserial.tx_free;
    if (txbuf) {
        vserial.tx_free = txbuf->next;
    }
    spin_unlock(&vserial.tx_lock);

    if (!txbuf) {
        /* Allocate new buffer */
        txbuf = allocate(vserial.general, sizeof(struct vserial_txbuf));
        if (txbuf == INVALID_ADDRESS)
            return 0;
        txbuf->buf = alloc_map(vserial.backed, VSERIAL_TX_BUFSIZE, &txbuf->phys);
        if (txbuf->buf == INVALID_ADDRESS) {
            deallocate(vserial.general, txbuf, sizeof(struct vserial_txbuf));
            return 0;
        }
        init_closure_func(&txbuf->complete, vqfinish, vserial_tx_complete);
    }

    return txbuf;
}

/* ============================================================
 * PUBLIC API
 * ============================================================ */

/*
 * Check if virtio-serial is connected.
 */
boolean virtio_serial_connected(void)
{
    return vserial.initialized && vserial.connected;
}

/*
 * Write data to virtio-serial.
 * Returns bytes written, or negative error code.
 */
s64 virtio_serial_write(const void *data, u64 len)
{
    if (!vserial.initialized || !vserial.connected)
        return -ENOTCONN;

    if (len == 0)
        return 0;

    if (len > VSERIAL_TX_BUFSIZE)
        len = VSERIAL_TX_BUFSIZE;

    vserial_txbuf txbuf = vserial_alloc_txbuf();
    if (!txbuf)
        return -ENOMEM;

    runtime_memcpy(txbuf->buf, data, len);
    txbuf->len = len;

    vserial_debug("%s: sending %ld bytes\n", func_ss, len);

    vqmsg m = allocate_vqmsg(vserial.txq);
    if (m == INVALID_ADDRESS) {
        /* Return buffer to free list */
        spin_lock(&vserial.tx_lock);
        txbuf->next = vserial.tx_free;
        vserial.tx_free = txbuf;
        spin_unlock(&vserial.tx_lock);
        return -ENOMEM;
    }

    /* Host reads from this buffer */
    vqmsg_push(vserial.txq, m, txbuf->phys, len, false);
    vqmsg_commit(vserial.txq, m, (vqfinish)&txbuf->complete);

    return len;
}

/*
 * Read data from virtio-serial.
 * Returns bytes read, 0 if no data available, or negative error code.
 * Non-blocking.
 */
s64 virtio_serial_read(void *buf, u64 len)
{
    if (!vserial.initialized || !vserial.connected)
        return -ENOTCONN;

    if (len == 0)
        return 0;

    /* Check if we have data */
    if (vserial.rx_ready_count == 0)
        return 0;

    vserial_rxbuf rxbuf = vserial.rx_head;
    if (rxbuf->pending || rxbuf->len == 0)
        return 0;

    /* Copy available data */
    u64 available = rxbuf->len - rxbuf->consumed;
    u64 to_copy = MIN(len, available);

    runtime_memcpy(buf, rxbuf->buf + rxbuf->consumed, to_copy);
    rxbuf->consumed += to_copy;

    vserial_debug("%s: read %ld bytes (consumed %ld/%ld)\n",
                  func_ss, to_copy, rxbuf->consumed, rxbuf->len);

    /* If buffer fully consumed, recycle it */
    if (rxbuf->consumed >= rxbuf->len) {
        fetch_and_add(&vserial.rx_ready_count, -1);
        vserial.rx_head = rxbuf->next;
        vserial_post_rx(rxbuf);
    }

    return to_copy;
}

/*
 * Read a line from virtio-serial (up to newline or maxlen).
 * Returns bytes read (including newline if found), or negative error.
 * This is a polling read that may block.
 */
s64 virtio_serial_read_line(void *buf, u64 maxlen, u64 timeout_ms)
{
    if (!vserial.initialized || !vserial.connected)
        return -ENOTCONN;

    u64 total = 0;
    u8 *out = buf;
    u64 start = 0; /* TODO: get current time for timeout */
    (void)start;
    (void)timeout_ms;

    while (total < maxlen) {
        u8 c;
        s64 n = virtio_serial_read(&c, 1);
        if (n < 0)
            return n;
        if (n == 0) {
            /* No data, yield and retry */
            kern_pause();
            continue;
        }

        out[total++] = c;
        if (c == '\n')
            break;
    }

    return total;
}

/* ============================================================
 * DEVICE INITIALIZATION
 * ============================================================ */

static boolean virtio_serial_attach(heap general, backed_heap backed, vtdev v)
{
    vserial_debug("%s: dev_features 0x%lx\n", func_ss, v->dev_features);

    vserial.general = general;
    vserial.backed = backed;
    vserial.dev = v;
    vserial.initialized = false;
    vserial.connected = false;
    vserial.tx_free = 0;
    spin_lock_init(&vserial.tx_lock);

    /* Allocate receive queue (queue 0) */
    status s = virtio_alloc_virtqueue(v, ss("virtio serial rxq"), 0, &vserial.rxq);
    if (!is_ok(s)) {
        msg_err("vserial: failed to allocate rxq: %v\n", s);
        goto fail;
    }

    /* Allocate transmit queue (queue 1) */
    s = virtio_alloc_virtqueue(v, ss("virtio serial txq"), 1, &vserial.txq);
    if (!is_ok(s)) {
        msg_err("vserial: failed to allocate txq: %v\n", s);
        goto fail;
    }

    vserial_debug("%s: virtqueues allocated\n", func_ss);

    /* Set driver OK status */
    vtdev_set_status(v, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    /* Initialize receive buffers */
    vserial_init_rx();

    vserial.initialized = true;
    vserial.connected = true;

    vserial_debug("%s: initialization complete\n", func_ss);
    return true;

fail:
    return false;
}

closure_function(2, 1, boolean, vtpci_serial_probe,
                 heap, general, backed_heap, backed,
                 pci_dev d)
{
    vserial_debug("%s\n", func_ss);

    if (!vtpci_probe(d, VIRTIO_ID_CONSOLE))
        return false;

    vserial_debug("%s: attaching\n", func_ss);
    vtdev v = (vtdev)attach_vtpci(bound(general), bound(backed), d, 0);
    return virtio_serial_attach(bound(general), bound(backed), v);
}

void init_virtio_serial(kernel_heaps kh)
{
    vserial_debug("%s\n", func_ss);
    heap h = heap_locked(kh);
    backed_heap backed = heap_linear_backed(kh);
    register_pci_driver(closure(h, vtpci_serial_probe, h, backed), 0);
}
