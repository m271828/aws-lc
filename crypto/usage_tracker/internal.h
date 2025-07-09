#ifndef CRYPTO_USAGE_TRACKER_INTERNAL_H
#define CRYPTO_USAGE_TRACKER_INTERNAL_H

#include <openssl/usage_tracker.h>

enum FIPS_call_type_t {
  CALL_NOT_APPROVED = AWSLC_NOT_APPROVED,
  CALL_APPROVED = AWSLC_APPROVED,
  NOT_APPLICABLE
};

void log_function_call(const char *algorithm, enum FIPS_call_type_t status);

#endif
