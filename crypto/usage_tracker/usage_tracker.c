#include <openssl/obj.h>
#include "../asn1/internal.h"
#include "../crypto/internal.h"
#include "internal.h"

struct CRYPTO_STATIC_MUTEX lock = CRYPTO_STATIC_MUTEX_INIT;
log_call *logger = NULL;


void init_logging(log_call *log_cb) {
  CRYPTO_STATIC_MUTEX_lock_write(&lock);
  if (logger == NULL) {
    logger = log_cb;
  }
  CRYPTO_STATIC_MUTEX_unlock_write(&lock);
}

void log_function_call(const char *algorithm, enum FIPS_call_type_t status) {
  if (logger != NULL) {
    logger(algorithm, status);
  }
}
