#ifndef foocaformatutilhfoo
#define foocaformatutilhfoo

#include <inttypes.h>

#include "util.h"

const char *ca_format_type_name(uint64_t u);

int ca_with_feature_flags_parse_one(const char *name, uint64_t *ret);
int ca_with_feature_flags_format(uint64_t features, char **ret);

int ca_feature_flags_normalize(uint64_t flags, uint64_t *ret);
int ca_feature_flags_time_granularity_nsec(uint64_t flags, uint64_t *ret);

uint64_t ca_feature_flags_from_chattr(unsigned flags);
unsigned ca_feature_flags_to_chattr(uint64_t flags);

uint64_t ca_feature_flags_from_fat_attrs(uint32_t flags);
uint32_t ca_feature_flags_to_fat_attrs(uint64_t flags);

uint64_t ca_feature_flags_from_magic(statfs_f_type_t type);

#endif
