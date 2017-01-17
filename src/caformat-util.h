#ifndef foocaformatutilhfoo
#define foocaformatutilhfoo

#include <inttypes.h>

const char *ca_format_type_name(uint64_t u);

int ca_feature_flags_parse_one(const char *name, uint64_t *ret);
int ca_feature_flags_format(uint64_t features, char **ret);

int ca_feature_flags_normalize(uint64_t flags, uint64_t *ret);
int ca_feature_flags_time_granularity_nsec(uint64_t flags, uint64_t *ret);

#endif
