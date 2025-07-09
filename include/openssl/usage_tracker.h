#ifndef OPENSSL_HEADER_USAGE_TRACKER_H
#define OPENSSL_HEADER_USAGE_TRACKER_H

typedef int (*log_call)(const char *algorithm, enum FIPS_call_type_t status);

OPENSSL_EXPORT void init_logging(log_call *log_cb);

#endif /* OPENSSL_HEADER_USAGE_TRACKER_H */
