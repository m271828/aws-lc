#ifndef CRYPTO_USAGE_TRACKER_INTERNAL_H
#define CRYPTO_USAGE_TRACKER_INTERNAL_H

#include <openssl/usage_tracker.h>

enum typename_t {
  // bool
  TYPE_BOOL,
  // char
  TYPE_CHAR,
  // signed char
  TYPE_SIGNED_CHAR,
  // unsigned char, uint8_t
  TYPE_UINT8_T,
  // short, short int, signed short, signed short int
  TYPE_SHORT,
  // unsigned short, unsigned short int
  TYPE_UNSIGNED_SHORT,
  // int, signed, signed int
  TYPE_INT,
  // unsigned, unsigned int
  TYPE_UNSIGNED,
  // long, long int, signed long int
  TYPE_LONG,
  // unsigned long, unsigned_long_int
  TYPE_UNSIGNED_LONG,
  // long long, long long int, signed long long, signed long long int
  TYPE_LONG_LONG,
  // float
  TYPE_FLOT,
  // double
  TYPE_DOUBLE,
  // long double
  TYPE_LONG_DOUBLE,
  // size_t
  TYPE_SIZE_T,
  // enum
  TYPE_ENUM,
  // struct
  TYPE_STRUCT,
  // union
  TYPE_UNION,
  // void
  TYPE_VOID,
  // Unknown
  TYPE_UNKNOWN,
  // Length
  TYPENAME_MAX
};

enum memory_types_t {
  SCALAR,
  POINTER,
  FIXED_LEN_ARRAY,
  ARRAY,
  MEMORY_TYPS_MAX
};

struct parameter_t {
  enum typename_t type;
  enum memory_types_t memory_type;
  const size_t *length;
  const void *value;
};

struct parameter_info_t {
  struct parameter_t *parameters;
  size_t length;
};

enum evp_typename_t {
  EVP_TYPE_MD_CTX,
  EVP_TYPE_UNKNOWN,
  EVP_TYPENAME_MAX
};

union evp_ctx_types_t {
  EVP_MD_CTX *mdctx;
};

struct evp_info_t {
  enum evp_typename_t type;
  union evp_ctx_types_t *ctx;
  struct parameter_info_t *params;
};

struct parameter_t *construct_parameter(enum typename_t type, const void *value);
struct parameter_t *construct_pointer_parameter(enum typename_t type, const void *value);
struct parameter_t *construct_fixed_length_array_parameter(enum typename_t type, const size_t *length, const void *value);
struct parameter_t *construct_array_parameter(enum typename_t type, const size_t *length, const void *value);
void delete_parameter(struct parameter_t *parameter);

struct parameter_info_t *init_parameter_info();
void add_parameter(struct parameter_info_t *parameters, struct parameter_t *parameter);
void delete_parameter_info(struct parameter_info_t *parameter_info);

struct evp_info_t *init_evp_info(enum evp_typename_t type, void *ctx);
void delete_evp_info(struct evp_info_t *info);

void log_evp_layer_call(const char *algorithm);
void log_evp_layer_call(const char *algorithm, struct evp_info_t *info);
void log_function_call(const char *algorithm);
void log_function_call(const char *algorithm, enum FIPSStatus status);
void log_function_call(const char *algorithm, const struct parameter_info_t *params);
void log_function_call(const char *algorithm, const struct parameter_info_t *params, enum FIPSStatus status);

int logging_enabled();
int include_fips();
int include_params();
int include_evp_calls();
int include_evp_params();

#endif
