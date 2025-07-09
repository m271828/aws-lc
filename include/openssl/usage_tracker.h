#ifndef OPENSSL_HEADER_USAGE_TRACKER_H
#define OPENSSL_HEADER_USAGE_TRACKER_H

typedef struct evp_info_t EVP_INFO;
typedef struct parameter_info_t PARAMETER_INFO;

typedef int (*log_call)(const char *algorithm);
typedef int (*log_evp_call)(const EVP_INFO *evp_info);
typedef int (*log_call_and_fips_status)(const char *algorithm, enum FIPSStatus status);
typedef int (*log_call_with_params)(const char *algorithm, const PARAMETER_INFO *params);
typedef int (*log_call_with_params_and_fips_status)(const char *algorithm, const PARAMETER_INFO *params, enum FIPSStatus status);

OPENSSL_EXPORT void init_logging(log_call *log_call,
                         log_evp_call *log_evp_call,
                         log_call_and_fips_status *log_call_and_fips_status,
                         log_call_with_params *log_call_with_params,
                         log_call_with_params_and_fips_status *log_call_with_params_and_fips_status);

#endif /* OPENSSL_HEADER_USAGE_TRACKER_H */
