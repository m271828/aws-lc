#ifndef CRYPTO_USAGE_TRACKER_INTERNAL_H
#define CRYPTO_USAGE_TRACKER_INTERNAL_H

#include <openssl/usage_tracker.h>
#include <openssl/service_indicator.h>
#include "../crypto/internal.h"

struct crypto_usage_st {
  CRYPTO_refcount_t total_usage;
  CRYPTO_refcount_t fips_usage;
};

enum algorithm_log_t {
  LOG_MD5,
  LOG_AES,
  LOG_ALGORITHM_COUNT
};

void crypto_usage_update_state(enum algorithm_log_t algorithm, enum FIPSStatus fips_status);

#endif
