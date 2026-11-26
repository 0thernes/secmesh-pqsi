/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * SecMesh-PQSI v3.0 — Cross-Platform Layer-3 Virtual NIC (Linux TUN / Windows Wintun)
 * & RFC 791 IPv4 Packet Validation Interface.
 */
#ifndef SECMESH_TUN_H
#define SECMESH_TUN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECMESH_TUN_OK                 0
#define SECMESH_TUN_ERR_INVALID       -1
#define SECMESH_TUN_ERR_NO_DRIVER     -2
#define SECMESH_TUN_ERR_PRIVILEGE     -3
#define SECMESH_TUN_ERR_IO            -4
#define SECMESH_TUN_ERR_UNSUPPORTED   -5

typedef struct {
    int   supported_os;
    int   driver_available;     /* Linux: /dev/net/tun exists; Windows: wintun.dll loadable */
    int   has_privilege;        /* Linux: euid==0 / openable; Windows: elevated admin token */
    char  backend[32];          /* "linux-tun", "windows-wintun", or "unsupported" */
    char  detail[160];
} secmesh_tun_probe_t;

typedef struct secmesh_tun_handle secmesh_tun_handle_t;

/* Non-destructive probe of OS TUN / Wintun readiness (never mutates host state). */
void secmesh_tun_probe(secmesh_tun_probe_t *out);

/* Open a real OS Layer-3 TUN interface (requires root/CAP_NET_ADMIN on Linux or
 * Administrator + wintun.dll on Windows). Returns SECMESH_TUN_OK on success. */
int  secmesh_tun_open(const char *ifname, secmesh_tun_handle_t **out_handle);
int  secmesh_tun_read(secmesh_tun_handle_t *h, uint8_t *buf, size_t cap, size_t *out_len);
int  secmesh_tun_write(secmesh_tun_handle_t *h, const uint8_t *pkt, size_t len);
void secmesh_tun_close(secmesh_tun_handle_t *h);

/* RFC 791 IPv4 header inspection & checksum (used by both OS TUN and userspace VirtualMesh). */
typedef struct {
    uint8_t  version;
    uint8_t  ihl_bytes;
    uint16_t total_len;
    uint8_t  ttl;
    uint8_t  protocol;
    uint32_t src_ip_be;
    uint32_t dst_ip_be;
    int      checksum_valid;
} secmesh_ipv4_hdr_t;

uint16_t secmesh_ipv4_checksum(const uint8_t *hdr, size_t ihl_bytes);
int      secmesh_ipv4_parse(const uint8_t *pkt, size_t len, secmesh_ipv4_hdr_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECMESH_TUN_H */
