/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * Health-tested, Bell-gated, SHAKE256 + Toeplitz conditioned entropy engine
 * built directly on Moonlab's MIT-licensed NIST SP 800-90B health_tests.c,
 * sha3.c (FIPS 202), and qrng_di.c (Pironio H_min + Toeplitz extractor).
 */
#include "secmesh_pqsi.h"
#include "../third_party/moonlab/applications/moonlab_export.h"
#include "../third_party/moonlab/applications/health_tests.h"
#include "../third_party/moonlab/applications/qrng_di.h"
#include "../third_party/moonlab/crypto/sha3/sha3.h"

#include <math.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/mman.h>
#include <sys/random.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#else
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

/* =========================================================================
 * Constant-Time & Zeroization Utilities
 * ========================================================================= */
void secmesh_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

int secmesh_ct_memeq(const uint8_t *a, const uint8_t *b, size_t len) {
    if (len > 0 && (!a || !b)) return 0;
    volatile const uint8_t *va = (volatile const uint8_t *)a;
    volatile const uint8_t *vb = (volatile const uint8_t *)b;
    uint32_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint32_t)(va[i] ^ vb[i]);
    }
    /* Compiler optimization barrier + branchless equality mask (1 iff diff == 0) */
    __asm__ __volatile__("" : "+r"(diff) :: "memory");
    return (int)((diff - 1u) >> 31);
}

int secmesh_mem_lock(void *ptr, size_t len) {
    if (!ptr || len == 0) return -1;
#ifdef _WIN32
    return VirtualLock(ptr, len) ? 0 : -1;
#else
    return (mlock(ptr, len) == 0) ? 0 : -1;
#endif
}

int secmesh_mem_unlock(void *ptr, size_t len) {
    if (!ptr || len == 0) return -1;
#ifdef _WIN32
    return VirtualUnlock(ptr, len) ? 0 : -1;
#else
    return (munlock(ptr, len) == 0) ? 0 : -1;
#endif
}

int secmesh_sp80090b_audit_buffer(const uint8_t *buf, size_t len) {
    if (!buf || len < 512) return -1;
    health_test_ctx_t ht;
    if (health_tests_init(&ht) != HEALTH_SUCCESS) return -1;
    int rc = (health_tests_run_batch(&ht, buf, len) == HEALTH_SUCCESS) ? 0 : -2;
    health_tests_free(&ht);
    secmesh_secure_zero(&ht, sizeof ht);
    return rc;
}

/* =========================================================================
 * OS Hardware CSPRNG
 * ========================================================================= */
int secmesh_os_csprng(uint8_t *out, size_t len) {
    if (!out || len == 0) return -1;
#ifdef _WIN32
    size_t done = 0;
    while (done < len) {
        size_t rem = len - done;
        ULONG chunk = (rem > 0x40000000ULL) ? (ULONG)0x40000000UL : (ULONG)rem;
        NTSTATUS st = BCryptGenRandom(NULL, out + done, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (st < 0) return -1;
        done += (size_t)chunk;
    }
    return 0;
#elif defined(__linux__)
    size_t done = 0;
    while (done < len) {
        ssize_t n = getrandom(out + done, len - done, 0);
        if (n > 0) {
            done += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    if (done == len) return 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (done < len) {
        ssize_t n = read(fd, out + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return -1; }
        done += (size_t)n;
    }
    close(fd);
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, out + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return -1; }
        done += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

/* =========================================================================
 * Exact Singlet CHSH Epoch Check (fixes SecMesh v1's super-quantum 0.146 bug!)
 * Exact quantum singlet probabilities for optimal CHSH angles:
 *   P(agree | (a,b) in {(0,0),(0,1),(1,0)}) = sin^2(pi/8) = (2 - sqrt(2)) / 4
 *   P(agree | (a,b) = (1,1))                = cos^2(pi/8) = (2 + sqrt(2)) / 4
 * Theoretical expectation: E_00 + E_01 + E_10 - E_11 = -2*sqrt(2), |S| = 2*sqrt(2).
 * NOTE: This is a software Born-rule state-vector health epoch driven by OS CSPRNG,
 * NOT physical photonic device-independence (explicitly flagged in status).
 * ========================================================================= */
static double run_exact_singlet_bell_epoch(const uint8_t *entropy_buf, size_t n_trials) {
    /* Exact constants: (2 - sqrt(2))/4 = 0.14644660940672624,
     *                  (2 + sqrt(2))/4 = 0.85355339059327376 */
    const double p_anti = (2.0 - 1.41421356237309504880) * 0.25;
    const double p_corr = (2.0 + 1.41421356237309504880) * 0.25;
    int64_t sums[4] = {0, 0, 0, 0};
    uint64_t cnts[4] = {0, 0, 0, 0};

    for (size_t i = 0; i < n_trials; i++) {
        /* 8 bytes per trial: 1 byte setting selector, 7 bytes -> 53-bit uniform double */
        const uint8_t *p = entropy_buf + i * 8;
        uint32_t cell = (uint32_t)(p[0] & 3u);
        uint64_t u53 = ((uint64_t)p[1])
                     | ((uint64_t)p[2] << 8)
                     | ((uint64_t)p[3] << 16)
                     | ((uint64_t)p[4] << 24)
                     | ((uint64_t)p[5] << 32)
                     | ((uint64_t)p[6] << 40)
                     | ((uint64_t)(p[7] & 0x1Fu) << 48);
        double u = (double)u53 / 9007199254740992.0; /* 2^53 */
        double thresh = (cell == 3u) ? p_corr : p_anti;
        int e = (u < thresh) ? 1 : -1;
        sums[cell] += e;
        cnts[cell] += 1;
    }
    if (!cnts[0] || !cnts[1] || !cnts[2] || !cnts[3]) return 0.0;
    double s = (double)sums[0] / (double)cnts[0]
             + (double)sums[1] / (double)cnts[1]
             + (double)sums[2] / (double)cnts[2]
             - (double)sums[3] / (double)cnts[3];
    return fabs(s);
}

static secmesh_entropy_status_t g_status = {0, 0, 0, 0, 0.0, 0.0, 0, 0};
static health_test_ctx_t g_health_ctx;
static int g_health_init = 0;
static uint64_t g_epoch_counter = 0;

static int ensure_health_init(void) {
    if (g_health_init) return 0;
    if (health_tests_init(&g_health_ctx) != HEALTH_SUCCESS) return -1;
    uint8_t startup[1024];
    if (secmesh_os_csprng(startup, sizeof startup) != 0) {
        health_tests_free(&g_health_ctx);
        return -1;
    }
    if (health_tests_startup(&g_health_ctx, startup, sizeof startup) != HEALTH_SUCCESS) {
        secmesh_secure_zero(startup, sizeof startup);
        health_tests_free(&g_health_ctx);
        g_status.health_failures++;
        return -1;
    }
    secmesh_secure_zero(startup, sizeof startup);
    g_health_init = 1;
    return 0;
}

int moonlab_qrng_bytes(uint8_t *out, size_t len) {
    if (!out || len == 0) return -1;
    if (ensure_health_init() != 0) return -1;

    /* Run a Bell-state epoch check on first call and every 64 requests */
    if (g_status.bell_epochs_passed == 0 || (g_epoch_counter % 64ULL) == 0) {
        enum { BELL_TRIALS = 2048 };
        uint8_t bell_raw[BELL_TRIALS * 8];
        if (secmesh_os_csprng(bell_raw, sizeof bell_raw) != 0) {
            secmesh_secure_zero(out, len);
            return -1;
        }
        /* Continuous SP 800-90B health test on first 512 bytes of epoch raw */
        if (health_tests_run_batch(&g_health_ctx, bell_raw, 512) != HEALTH_SUCCESS) {
            secmesh_secure_zero(bell_raw, sizeof bell_raw);
            secmesh_secure_zero(out, len);
            g_status.health_failures++;
            return -1;
        }
        double s = run_exact_singlet_bell_epoch(bell_raw, BELL_TRIALS);
        secmesh_secure_zero(bell_raw, sizeof bell_raw);
        if (s <= 2.40) {
            /* Fail closed: zeroize output and refuse delivery */
            secmesh_secure_zero(out, len);
            g_status.health_failures++;
            return -1;
        }
        g_status.last_chsh_s = s;
        g_status.last_pironio_hmin = qrng_di_min_entropy_from_chsh(s);
        g_status.bell_epochs_passed++;
    }

    /* Draw 2x raw entropy for Toeplitz 2-universal extraction + SHAKE256 conditioning */
    uint8_t raw_in[128];
    uint8_t toeplitz_seed[192];
    uint8_t extracted[64];
    if (secmesh_os_csprng(raw_in, sizeof raw_in) != 0 ||
        secmesh_os_csprng(toeplitz_seed, sizeof toeplitz_seed) != 0) {
        secmesh_secure_zero(raw_in, sizeof raw_in);
        secmesh_secure_zero(toeplitz_seed, sizeof toeplitz_seed);
        secmesh_secure_zero(out, len);
        return -1;
    }
    if (health_tests_run_batch(&g_health_ctx, raw_in, sizeof raw_in) != HEALTH_SUCCESS) {
        secmesh_secure_zero(raw_in, sizeof raw_in);
        secmesh_secure_zero(toeplitz_seed, sizeof toeplitz_seed);
        secmesh_secure_zero(out, len);
        g_status.health_failures++;
        return -1;
    }
    if (qrng_di_toeplitz_extract(raw_in, sizeof raw_in,
                                 toeplitz_seed, sizeof toeplitz_seed,
                                 extracted, sizeof extracted) != 0) {
        secmesh_secure_zero(raw_in, sizeof raw_in);
        secmesh_secure_zero(toeplitz_seed, sizeof toeplitz_seed);
        secmesh_secure_zero(out, len);
        return -1;
    }

    /* Domain-separated SHAKE256 conditioner combining Toeplitz output + fresh OS entropy */
    sha3_ctx_t ctx;
    shake256_init(&ctx);
    const char domain[] = "SecMesh-PQSI-v2.0|Moonlab-SP800-90B-Toeplitz-SHAKE256";
    sha3_update(&ctx, (const uint8_t *)domain, sizeof(domain) - 1);
    uint64_t ctr = ++g_epoch_counter;
    uint8_t ctr_le[8];
    for (int i = 0; i < 8; i++) ctr_le[i] = (uint8_t)((ctr >> (8 * i)) & 0xFFu);
    sha3_update(&ctx, ctr_le, sizeof ctr_le);
    sha3_update(&ctx, extracted, sizeof extracted);
    sha3_update(&ctx, raw_in, 32);
    shake_squeeze(&ctx, out, len);

    secmesh_secure_zero(&ctx, sizeof ctx);
    secmesh_secure_zero(raw_in, sizeof raw_in);
    secmesh_secure_zero(toeplitz_seed, sizeof toeplitz_seed);
    secmesh_secure_zero(extracted, sizeof extracted);

    g_status.requests_served++;
    g_status.bytes_served += len;
    return 0;
}

int secmesh_entropy_get_status(secmesh_entropy_status_t *out_status) {
    if (!out_status) return -1;
    *out_status = g_status;
    return 0;
}

int secmesh_entropy_self_test(void) {
    uint8_t buf[64];
    int rc = moonlab_qrng_bytes(buf, sizeof buf);
    secmesh_secure_zero(buf, sizeof buf);
    return rc;
}
