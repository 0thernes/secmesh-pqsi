/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * Cross-Platform Layer-3 TUN / Wintun Adapter & RFC 791 IPv4 Validator.
 * - Linux:   real /dev/net/tun (IFF_TUN | IFF_NO_PI) via ioctl(TUNSETIFF)
 * - Windows: real dynamic WireGuard wintun.dll ABI via LoadLibraryA
 * - Always fails closed with honest diagnostic codes when unprivileged or driver absent.
 */
#include "secmesh_tun.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Official WireGuard Wintun C ABI (wintun.h) */
typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;
typedef WINTUN_ADAPTER_HANDLE (WINAPI *fn_WintunCreateAdapter)(const wchar_t *, const wchar_t *, const GUID *);
typedef void                  (WINAPI *fn_WintunCloseAdapter)(WINTUN_ADAPTER_HANDLE);
typedef WINTUN_SESSION_HANDLE (WINAPI *fn_WintunStartSession)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef void                  (WINAPI *fn_WintunEndSession)(WINTUN_SESSION_HANDLE);
typedef HANDLE                (WINAPI *fn_WintunGetReadWaitEvent)(WINTUN_SESSION_HANDLE);
typedef BYTE *                (WINAPI *fn_WintunReceivePacket)(WINTUN_SESSION_HANDLE, DWORD *);
typedef void                  (WINAPI *fn_WintunReleaseReceivePacket)(WINTUN_SESSION_HANDLE, const BYTE *);
typedef BYTE *                (WINAPI *fn_WintunAllocateSendPacket)(WINTUN_SESSION_HANDLE, DWORD);
typedef void                  (WINAPI *fn_WintunSendPacket)(WINTUN_SESSION_HANDLE, const BYTE *);

struct secmesh_tun_handle {
    HMODULE dll;
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    fn_WintunCloseAdapter close_adapter;
    fn_WintunEndSession end_session;
    fn_WintunGetReadWaitEvent get_wait_event;
    fn_WintunReceivePacket recv_pkt;
    fn_WintunReleaseReceivePacket rel_pkt;
    fn_WintunAllocateSendPacket alloc_send;
    fn_WintunSendPacket send_pkt;
};

static int win_is_elevated(void) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    TOKEN_ELEVATION elev;
    DWORD sz = sizeof(elev);
    int res = 0;
    if (GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz)) {
        res = elev.TokenIsElevated ? 1 : 0;
    }
    CloseHandle(tok);
    return res;
}

#elif defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

struct secmesh_tun_handle {
    int  fd;
    char ifname[IFNAMSIZ];
};
#else
struct secmesh_tun_handle {
    int dummy;
};
#endif

static int valid_ifname(const char *name) {
    if (!name || !*name) return 0;
    size_t n = strlen(name);
    if (n == 0 || n > 15) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '_' && c != '-') return 0;
    }
    return 1;
}

void secmesh_tun_probe(secmesh_tun_probe_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
#ifdef _WIN32
    out->supported_os = 1;
    snprintf(out->backend, sizeof(out->backend), "windows-wintun");
    out->has_privilege = win_is_elevated();
    HMODULE mod = LoadLibraryA("wintun.dll");
    if (mod) {
        out->driver_available = 1;
        FreeLibrary(mod);
    }
    if (!out->driver_available) {
        snprintf(out->detail, sizeof(out->detail),
                 "wintun.dll not found on PATH/System32 (download official signed wintun.dll from wintun.net for kernel L3 NIC; userspace L3 VPN works without admin)");
    } else if (!out->has_privilege) {
        snprintf(out->detail, sizeof(out->detail),
                 "wintun.dll found; Administrator elevation required to create kernel Wintun NIC (userspace L3 VPN active)");
    } else {
        snprintf(out->detail, sizeof(out->detail), "wintun.dll loaded and Administrator privilege available");
    }
#elif defined(__linux__)
    out->supported_os = 1;
    snprintf(out->backend, sizeof(out->backend), "linux-tun");
    struct stat st;
    if (stat("/dev/net/tun", &st) == 0) out->driver_available = 1;
    out->has_privilege = (geteuid() == 0) ? 1 : 0;
    if (!out->driver_available) {
        snprintf(out->detail, sizeof(out->detail), "/dev/net/tun absent (tun kernel module not loaded; userspace L3 VPN active)");
    } else if (!out->has_privilege) {
        snprintf(out->detail, sizeof(out->detail), "/dev/net/tun present; root or CAP_NET_ADMIN needed for kernel TUN (userspace L3 VPN active)");
    } else {
        snprintf(out->detail, sizeof(out->detail), "/dev/net/tun ready with root privileges");
    }
#else
    out->supported_os = 0;
    snprintf(out->backend, sizeof(out->backend), "unsupported");
    snprintf(out->detail, sizeof(out->detail), "OS kernel TUN bridge not implemented for this platform (userspace L3 VPN active)");
#endif
}

int secmesh_tun_open(const char *ifname, secmesh_tun_handle_t **out_handle) {
    if (!valid_ifname(ifname) || !out_handle) return SECMESH_TUN_ERR_INVALID;
    *out_handle = NULL;
#ifdef _WIN32
    HMODULE dll = LoadLibraryA("wintun.dll");
    if (!dll) return SECMESH_TUN_ERR_NO_DRIVER;
    if (!win_is_elevated()) {
        FreeLibrary(dll);
        return SECMESH_TUN_ERR_PRIVILEGE;
    }
    fn_WintunCreateAdapter create_adapter = NULL;
    fn_WintunCloseAdapter close_adapter = NULL;
    fn_WintunStartSession start_session = NULL;
    fn_WintunEndSession end_session = NULL;
    fn_WintunGetReadWaitEvent get_wait = NULL;
    fn_WintunReceivePacket recv_pkt = NULL;
    fn_WintunReleaseReceivePacket rel_pkt = NULL;
    fn_WintunAllocateSendPacket alloc_send = NULL;
    fn_WintunSendPacket send_pkt = NULL;

    /* ISO-C compliant function-pointer loads via memcpy to avoid -Wpedantic warnings */
    FARPROC p;
    p = GetProcAddress(dll, "WintunCreateAdapter");        memcpy(&create_adapter, &p, sizeof(p));
    p = GetProcAddress(dll, "WintunCloseAdapter");         memcpy(&close_adapter,  &p, sizeof(p));
    p = GetProcAddress(dll, "WintunStartSession");         memcpy(&start_session,  &p, sizeof(p));
    p = GetProcAddress(dll, "WintunEndSession");           memcpy(&end_session,    &p, sizeof(p));
    p = GetProcAddress(dll, "WintunGetReadWaitEvent");     memcpy(&get_wait,       &p, sizeof(p));
    p = GetProcAddress(dll, "WintunReceivePacket");        memcpy(&recv_pkt,       &p, sizeof(p));
    p = GetProcAddress(dll, "WintunReleaseReceivePacket"); memcpy(&rel_pkt,        &p, sizeof(p));
    p = GetProcAddress(dll, "WintunAllocateSendPacket");   memcpy(&alloc_send,     &p, sizeof(p));
    p = GetProcAddress(dll, "WintunSendPacket");           memcpy(&send_pkt,       &p, sizeof(p));

    if (!create_adapter || !close_adapter || !start_session || !end_session ||
        !get_wait || !recv_pkt || !rel_pkt || !alloc_send || !send_pkt) {
        FreeLibrary(dll);
        return SECMESH_TUN_ERR_NO_DRIVER;
    }

    wchar_t wname[32];
    for (size_t i = 0; i < 31 && ifname[i]; i++) {
        wname[i] = (wchar_t)(unsigned char)ifname[i];
        wname[i + 1] = L'\0';
    }
    WINTUN_ADAPTER_HANDLE adapter = create_adapter(wname, L"SecMesh-PQSI", NULL);
    if (!adapter) {
        FreeLibrary(dll);
        return SECMESH_TUN_ERR_IO;
    }
    WINTUN_SESSION_HANDLE session = start_session(adapter, 0x400000); /* 4 MiB ring */
    if (!session) {
        close_adapter(adapter);
        FreeLibrary(dll);
        return SECMESH_TUN_ERR_IO;
    }
    secmesh_tun_handle_t *h = (secmesh_tun_handle_t *)calloc(1, sizeof(*h));
    if (!h) {
        end_session(session);
        close_adapter(adapter);
        FreeLibrary(dll);
        return SECMESH_TUN_ERR_IO;
    }
    h->dll = dll;
    h->adapter = adapter;
    h->session = session;
    h->close_adapter = close_adapter;
    h->end_session = end_session;
    h->get_wait_event = get_wait;
    h->recv_pkt = recv_pkt;
    h->rel_pkt = rel_pkt;
    h->alloc_send = alloc_send;
    h->send_pkt = send_pkt;
    *out_handle = h;
    return SECMESH_TUN_OK;
#elif defined(__linux__)
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return SECMESH_TUN_ERR_PRIVILEGE;
        return SECMESH_TUN_ERR_NO_DRIVER;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int e = errno;
        close(fd);
        return (e == EPERM || e == EACCES) ? SECMESH_TUN_ERR_PRIVILEGE : SECMESH_TUN_ERR_IO;
    }
    secmesh_tun_handle_t *h = (secmesh_tun_handle_t *)calloc(1, sizeof(*h));
    if (!h) { close(fd); return SECMESH_TUN_ERR_IO; }
    h->fd = fd;
    snprintf(h->ifname, IFNAMSIZ, "%s", ifr.ifr_name);
    *out_handle = h;
    return SECMESH_TUN_OK;
#else
    (void)ifname;
    return SECMESH_TUN_ERR_UNSUPPORTED;
#endif
}

int secmesh_tun_read(secmesh_tun_handle_t *h, uint8_t *buf, size_t cap, size_t *out_len) {
    if (!h || !buf || cap == 0 || !out_len) return SECMESH_TUN_ERR_INVALID;
    *out_len = 0;
#ifdef _WIN32
    DWORD pkt_sz = 0;
    BYTE *pkt = h->recv_pkt(h->session, &pkt_sz);
    if (!pkt) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS) return SECMESH_TUN_OK;
        return SECMESH_TUN_ERR_IO;
    }
    if ((size_t)pkt_sz > cap) {
        h->rel_pkt(h->session, pkt);
        return SECMESH_TUN_ERR_IO;
    }
    memcpy(buf, pkt, pkt_sz);
    *out_len = (size_t)pkt_sz;
    h->rel_pkt(h->session, pkt);
    return SECMESH_TUN_OK;
#elif defined(__linux__)
    ssize_t n;
    do {
        n = read(h->fd, buf, cap);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return SECMESH_TUN_ERR_IO;
    *out_len = (size_t)n;
    return SECMESH_TUN_OK;
#else
    return SECMESH_TUN_ERR_UNSUPPORTED;
#endif
}

int secmesh_tun_write(secmesh_tun_handle_t *h, const uint8_t *pkt, size_t len) {
    if (!h || !pkt || len == 0 || len > 65535u) return SECMESH_TUN_ERR_INVALID;
#ifdef _WIN32
    BYTE *dst = h->alloc_send(h->session, (DWORD)len);
    if (!dst) return SECMESH_TUN_ERR_IO;
    memcpy(dst, pkt, len);
    h->send_pkt(h->session, dst);
    return SECMESH_TUN_OK;
#elif defined(__linux__)
    ssize_t n;
    do {
        n = write(h->fd, pkt, len);
    } while (n < 0 && errno == EINTR);
    return (n == (ssize_t)len) ? SECMESH_TUN_OK : SECMESH_TUN_ERR_IO;
#else
    return SECMESH_TUN_ERR_UNSUPPORTED;
#endif
}

void secmesh_tun_close(secmesh_tun_handle_t *h) {
    if (!h) return;
#ifdef _WIN32
    if (h->session && h->end_session) h->end_session(h->session);
    if (h->adapter && h->close_adapter) h->close_adapter(h->adapter);
    if (h->dll) FreeLibrary(h->dll);
#elif defined(__linux__)
    if (h->fd >= 0) close(h->fd);
#endif
    free(h);
}

/* =========================================================================
 * RFC 791 IPv4 Header Validation & Internet Checksum
 * ========================================================================= */
uint16_t secmesh_ipv4_checksum(const uint8_t *hdr, size_t ihl_bytes) {
    if (!hdr || ihl_bytes < 20 || (ihl_bytes & 1u)) return 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < ihl_bytes; i += 2) {
        sum += ((uint32_t)hdr[i] << 8) | (uint32_t)hdr[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

int secmesh_ipv4_parse(const uint8_t *pkt, size_t len, secmesh_ipv4_hdr_t *out) {
    if (!pkt || !out || len < 20) return -1;
    memset(out, 0, sizeof(*out));
    uint8_t ver = (uint8_t)(pkt[0] >> 4);
    uint8_t ihl = (uint8_t)((pkt[0] & 0x0Fu) * 4u);
    if (ver != 4u || ihl < 20u || (size_t)ihl > len) return -2;
    uint16_t tot = (uint16_t)(((uint16_t)pkt[2] << 8) | pkt[3]);
    if (tot < ihl || (size_t)tot > len) return -3;
    out->version = ver;
    out->ihl_bytes = ihl;
    out->total_len = tot;
    out->ttl = pkt[8];
    out->protocol = pkt[9];
    out->src_ip_be = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
                     ((uint32_t)pkt[14] << 8)  | (uint32_t)pkt[15];
    out->dst_ip_be = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                     ((uint32_t)pkt[18] << 8)  | (uint32_t)pkt[19];
    out->checksum_valid = (secmesh_ipv4_checksum(pkt, ihl) == 0u) ? 1 : 0;
    return 0;
}
