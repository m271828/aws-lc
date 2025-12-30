/* ====================================================================
 * Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#ifndef OPENSSL_HEADER_ARM_ARCH_H
#define OPENSSL_HEADER_ARM_ARCH_H

#include <openssl/target.h>

/**
 * @file
 * @brief Contains symbols used by ARM assembly.
 *
 * @details
 * Contains symbols used by ARM assembly, and the C code that calls it.
 *
 * @warning It is included as a public header to simplify the build, but is not
 * intended for external use.
 */

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64) || defined(DOCUMENTATION_BUILD)

/**
 * @def ARMV7_NEON
 *
 * @brief True when a NEON unit is present in the current CPU.
 */
#define ARMV7_NEON (1 << 0)

/**
 * @def ARMV8_AES
 *
 * @brief Indicates support for hardware AES instructions.
 */
#define ARMV8_AES (1 << 2)

/**
 * @def ARMV8_SHA1
 *
 * @brief Indicates support for hardware SHA-1 instructions.
 */
#define ARMV8_SHA1 (1 << 3)

/**
 * @def ARMV8_SHA256
 *
 * @brief Indicates support for hardware SHA-256 instructions.
 */
#define ARMV8_SHA256 (1 << 4)

/**
 * @def ARMV8_PMULL
 *
 * @brief Indicates support for carryless multiplication.
 */
#define ARMV8_PMULL (1 << 5)

/**
 * @def ARMV8_SHA512
 *
 * @brief Indicates support for hardware SHA-512 instructions.
 */
#define ARMV8_SHA512 (1 << 6)

/**
 * @def ARMV8_SHA3
 *
 * @brief Indicates support for hardware SHA-3 instructions including EOR3.
 */
#define ARMV8_SHA3  (1 << 11)

/**
 * @name Armv8 Neon Extension Bits 0x087c
 *
 * @brief Combination of all Armv8 Neon extension bits: 0x087c
 *
 * @details
 * The Neoverse N1, V1, V2, and Apple M1 micro-architectures are detected to
 * allow selecting the fasted implementations for SHA3/SHAKE and AES-GCM.
 * Combination of all CPU indicator bits: 0x7080
 *
 * @note If you add further CPU indicator bits, adjust "Test algorithm dispatch
 * without CPU indicator bits" in util/all_tests.json.
 *
 * @note NOTE: If you add further Armv8 Neon extension bits, adjust "Test
 * algorithm dispatch without CPU indicator or Neon extension capability bits"
 * in util/all_tests.json
 *
 * @{
 */

#define ARMV8_NEOVERSE_N1 (1 << 7)
#define ARMV8_NEOVERSE_V1 (1 << 12)
#define ARMV8_APPLE_M (1 << 13)
#define ARMV8_NEOVERSE_V2 (1 << 14)

/** @} Armv8 Neon Extension Bits 0x087c */

/**
 * @name Combination of CPU indicator bits and Armv8 Neon extension bits 0x78fc
 *
 * @{
 */

/**
 * @def ARMV8_DIT
 *
 * @brief Indicates support for the Data-Independent Timing (DIT) flag.
 */
#define ARMV8_DIT (1 << 15)

/**
 * @def ARMV8_DIT_ALLOWED
 *
 * @brief A run-time en/disabler for the Data-Independent
 *
 * @details
 * Timing (DIT) flag capability. It makes the DIT capability allowed when it is
 * first discovered in `OPENSSL_cpuid_setup`. But that bit position in
 * `OPENSSL_armcap_P` can be toggled off and back on at run-time via
 * `armv8_disable_dit` and `armv8_enable_dit`, respectively.
 */
#define ARMV8_DIT_ALLOWED (1 << 16)

/**
 * @def ARMV8_RNG
 *
 * @brief Indicates supports for hardware RNG instruction RNDR.
 */
#define ARMV8_RNG (1 << 17)

/** @} Combination of CPU indicator bits and Armv8 Neon extension bits 0x78fc */

/**
 * @name MIDR_EL1 System Register
 *
 * @details
 * @verbatim
 * 63___ _ ___32_31___ _ ___24_23_____20_19_____16_15__ _ __4_3_______0
 * |            |             |         |         |          |        |
 * |RES0        | Implementer | Variant | Arch    | PartNum  |Revision|
 * |____ _ _____|_____ _ _____|_________|_______ _|____ _ ___|________|
 * @endverbatim
 *
 * @{
 */

# define ARM_CPU_IMP_ARM           0x41

# define ARM_CPU_PART_CORTEX_A72   0xD08
# define ARM_CPU_PART_N1           0xD0C
# define ARM_CPU_PART_V1           0xD40
# define ARM_CPU_PART_V2           0xD4F

# define MIDR_PARTNUM_SHIFT       4
# define MIDR_PARTNUM_MASK        (0xfffUL << MIDR_PARTNUM_SHIFT)
# define MIDR_PARTNUM(midr)       \
           (((midr) & MIDR_PARTNUM_MASK) >> MIDR_PARTNUM_SHIFT)

# define MIDR_IMPLEMENTER_SHIFT   24
# define MIDR_IMPLEMENTER_MASK    (0xffUL << MIDR_IMPLEMENTER_SHIFT)
# define MIDR_IMPLEMENTER(midr)   \
           (((midr) & MIDR_IMPLEMENTER_MASK) >> MIDR_IMPLEMENTER_SHIFT)

# define MIDR_ARCHITECTURE_SHIFT  16
# define MIDR_ARCHITECTURE_MASK   (0xfUL << MIDR_ARCHITECTURE_SHIFT)
# define MIDR_ARCHITECTURE(midr)  \
           (((midr) & MIDR_ARCHITECTURE_MASK) >> MIDR_ARCHITECTURE_SHIFT)

# define MIDR_CPU_MODEL_MASK \
           (MIDR_IMPLEMENTER_MASK | \
            MIDR_PARTNUM_MASK     | \
            MIDR_ARCHITECTURE_MASK)

# define MIDR_CPU_MODEL(imp, partnum) \
           (((imp)     << MIDR_IMPLEMENTER_SHIFT)  | \
            (0xfUL       << MIDR_ARCHITECTURE_SHIFT) | \
            ((partnum) << MIDR_PARTNUM_SHIFT))

# define MIDR_IS_CPU_MODEL(midr, imp, partnum) \
           (((midr) & MIDR_CPU_MODEL_MASK) == MIDR_CPU_MODEL(imp, partnum))

/** @} MIDR_EL1 System Register */
#endif  // ARM || AARCH64

#endif  // OPENSSL_HEADER_ARM_ARCH_H
