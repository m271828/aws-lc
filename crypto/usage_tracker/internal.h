#ifndef CRYPTO_USAGE_TRACKER_INTERNAL_H
#define CRYPTO_USAGE_TRACKER_INTERNAL_H

#include <openssl/usage_tracker.h>
#include <openssl/service_indicator.h>
#include "../crypto/internal.h"

enum algorithm_log_t {
  LOG_MD5,
  LOG_AES,
  LOG_ALGORITHM_COUNT
};

void crypto_usage_update_state(enum algorithm_log_t algorithm);

#endif
