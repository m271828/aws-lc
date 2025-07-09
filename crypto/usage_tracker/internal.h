#ifndef CRYPTO_USAGE_TRACKER_INTERNAL_H
#define CRYPTO_USAGE_TRACKER_INTERNAL_H

#include <openssl/usage_tracker.h>
#include <openssl/service_indicator.h>
#include "../crypto/internal.h"

struct crypto_usage_st {
  CRYPTO_refcount_t total_usage;
  CRYPTO_refcount_t fips_usage;
  CRYPTO_refcount_t evp_usage_count;
};

enum algorithm_log_t {
  LOG_MD5,
  LOG_AES,
  LOG_ALGORITHM_COUNT,
  LOG_INVALID
};

enum call_method_t {
  EVP_LAYER,
  DIRECT
};

void crypto_usage_update_state(enum algorithm_log_t algorithm, enum FIPSStatus fips_status);

void crypto_method_update_state(enum algorithm_log_t algorithm, enum call_method_t method);

enum algorithm_log_t nid_to_algorithm(int nid);

#endif
