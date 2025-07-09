#include <openssl/obj.h>
#include "../asn1/internal.h"
#include "../crypto/internal.h"
#include "internal.h"

CRYPTO_once_t initialized = CRYPTO_ONCE_INIT;
static CRYPTO_refcount_t usage[LOG_ALGORITHM_COUNT];

static void crypto_usage_init(void) {
  for (int i = 0; i < LOG_ALGORITHM_COUNT; i++) {
    usage[i] = 0;
  }
}

void crypto_usage_update_state(enum algorithm_log_t id) {
  CRYPTO_once(&initialized, crypto_usage_init);
  CRYPTO_refcount_inc(&usage[id]);
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
    if (usage[i] != 0) {
      if ((*cb)(lookup_algorithm_name(i), usage[i]) <= 0) {
        break;
      }
    }
  }
}
