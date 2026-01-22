/*
 * VirtIO Serial/Console Driver Header
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 */

#ifndef VIRTIO_SERIAL_H
#define VIRTIO_SERIAL_H

/*
 * This header is included by kernel code that already has kernel types.
 * The actual init function is declared in src/virtio/virtio.h.
 * These APIs are for the ak_virtio_proxy to use.
 */

/* Check if connected */
int virtio_serial_connected(void);

/* Write data (non-blocking, may return partial) */
long long virtio_serial_write(const void *data, unsigned long long len);

/* Read data (non-blocking, returns 0 if no data) */
long long virtio_serial_read(void *buf, unsigned long long len);

/* Read line (blocking with timeout) */
long long virtio_serial_read_line(void *buf, unsigned long long maxlen, unsigned long long timeout_ms);

#endif /* VIRTIO_SERIAL_H */
