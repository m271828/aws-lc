#ifndef OPENSSL_HEADER_USAGE_TRACKER_H
#define OPENSSL_HEADER_USAGE_TRACKER_H

typedef int (*read_crypto_usage_t)(const char *algorithm, const CRYPTO_refcount_t total);

void get_crypto_usage(read_crypto_usage_t *cb);

#endif /* OPENSSL_HEADER_USAGE_TRACKER_H */
