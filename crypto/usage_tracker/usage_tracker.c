#include <openssl/obj.h>
#include "../asn1/internal.h"
#include "../crypto/internal.h"
#include "internal.h"

struct CRYPTO_STATIC_MUTEX lock = CRYPTO_STATIC_MUTEX_INIT;
int initialized = 0;
log_call *log;
log_evp_call *log_evp;
log_call_and_fips_status *log_with_fips_status;
log_call_with_params *log_with_params;
log_call_with_params_and_fips_status *log_with_params_and_fips_status;


void init_logging(log_call *log_call,
                  log_evp_call *log_evp_call,
                  log_call_and_fips_status *log_call_and_fips_status,
                  log_call_with_params *log_call_with_params,
                  log_call_with_params_and_fips_status *log_call_with_params_and_fips_status) {
  CRYPTO_STATIC_MUTEX_lock_write(&lock);
  if (initialized == 0) {
    initialized = 1;
    log = log_call;
    log_evp = log_evp_call;
    log_with_fips_status = log_call_and_fips_status;
    log_with_params = log_call_with_params;
    log_with_params_and_fips_status = log_call_with_params_and_fips_status;
  }
  CRYPTO_STATIC_MUTEX_unlock_write(&lock);
}

int logging_enabled() {
  return log != NULL;
}

int include_fips() {
  return log_with_fips_status != NULL;
}

int include_params() {
  return log_with_params != NULL;
}

int include_evp_calls() {
  return log_evp != NULL;
}

int include_evp_params() {
  return log_with_params != NULL;
}