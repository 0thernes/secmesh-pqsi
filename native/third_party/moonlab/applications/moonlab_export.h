/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MOONLAB_EXPORT_H
#define MOONLAB_EXPORT_H

#include <stddef.h>
#include <stdint.h>
#include "moonlab_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate @p len bytes of health-tested, Bell-gated, SHAKE256-conditioned
 *        entropy via the SecMesh-PQSI entropy pipeline (built on Moonlab's
 *        SP 800-90B health tests and Toeplitz extractor).
 * @return 0 on success, non-zero on health-test or OS CSPRNG failure.
 */
MOONLAB_API int moonlab_qrng_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MOONLAB_EXPORT_H */
