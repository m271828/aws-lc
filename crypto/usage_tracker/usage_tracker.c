#include <openssl/obj.h>
#include "../asn1/internal.h"
#include "../crypto/internal.h"
#include "internal.h"

CRYPTO_once_t initialized = CRYPTO_ONCE_INIT;
static struct crypto_usage_st usage[LOG_ALGORITHM_COUNT];

static void crypto_usage_init(void) {
  for (int i = 0; i < LOG_ALGORITHM_COUNT; i++) {
    usage[i].total_usage = 0;
    usage[i].fips_usage = 0;
    usage[i].evp_usage_count = 0;
  }
}

void crypto_usage_update_state(enum algorithm_log_t id, enum FIPSStatus fips_status) {
  CRYPTO_once(&initialized, crypto_usage_init);
  CRYPTO_refcount_inc(&usage[id].total_usage);
  if (fips_status == AWSLC_APPROVED) {
    CRYPTO_refcount_inc(&usage[id].fips_usage);
  }
}

void crypto_method_update_state(enum algorithm_log_t id, enum call_method_t method) {
  CRYPTO_once(&initialized, crypto_usage_init);
  if (method == EVP_LAYER) {
    CRYPTO_refcount_inc(&usage[id].evp_usage_count);
  }
}

enum algorithm_log_t nid_to_algorithm(int nid) {
  switch (nid) {
    case NID_md5:
      return LOG_MD5;
    case NID_aes_128_cbc:
    case NID_aes_128_cbc_hmac_sha1:
    case NID_aes_128_cbc_hmac_sha256:
    case NID_aes_128_ccm:
    case NID_aes_128_cfb1:
    case NID_aes_128_cfb8:
    case NID_aes_128_cfb128:
    case NID_aes_128_ctr:
    case NID_aes_128_ecb:
    case NID_aes_128_gcm:
    case NID_aes_128_ofb128:
    case NID_aes_128_xts:
    case NID_aes_192_cbc:
    case NID_aes_192_cbc_hmac_sha1:
    case NID_aes_192_ccm:
    case NID_aes_192_cfb1:
    case NID_aes_192_cfb8:
    case NID_aes_192_cfb128:
    case NID_aes_192_ctr:
    case NID_aes_192_ecb:
    case NID_aes_192_gcm:
    case NID_aes_192_ofb128:
    case NID_aes_256_cbc:
    case NID_aes_256_cbc_hmac_sha256:
    case NID_aes_256_ccm;
    case NID_aes_256_cfb1:
    case NID_aes_256_cfb8:
    case NID_aes_256_cfb128:
    case NID_aes_256_ctr:
    case NID_aes_256_ecb:
    case NID_aes_256_gcm:
    case NID_aes_256_ofb128:
    case NID_aes_256_xts:
      return LOG_AES;
    default:
      return LOG_INVALID;
  }
}

#define MD5_STR "md5\0"
#define AES_STR "aes (generic)\0"

static const char* lookup_algorithm_name(enum algorithm_log_t id) {
  switch (id) {
    case LOG_AES:
      return AES_STR;
    case LOG_MD5:
      return MD5_STR;
    default:
      return NULL;
  }
}

void get_crypto_usage(read_crypto_usage_t *cb) {
  for (int i = 0; i < LOG_ALGORITHM_COUNT; i++) {
    if (usage[i].total_usage != 0) {
      if ((*cb)(lookup_algorithm_name(i), usage[i].total_usage, usage[i].fips_usage, usage[i].evp_usage_count) <= 0) {
        break;
      }
    }
  }
}
