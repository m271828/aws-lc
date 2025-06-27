#ifndef OPENSSL_HEADER_USAGE_TRACKER_H
#define OPENSSL_HEADER_USAGE_TRACKER_H

typedef struct crypto_usage_st CRYPTO_USAGE;

typedef int (*read_crypto_usage_t)(const char *algorithm, const CRYPTO_refcount_t total, const CRYPTO_refcount_t fips_usage);

void get_crypto_usage(read_crypto_usage_t *cb);

#endif /* OPENSSL_HEADER_USAGE_TRACKER_H */
