#ifndef foocaencoderhfoo
#define foocaencoderhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct CaEncoder CaEncoder;

enum {
        CA_ENCODER_FINISHED,  /* The end of the stream has been reached */
        CA_ENCODER_NEXT_FILE, /* We started with the next file, and we generated some data */
        CA_ENCODER_DATA,      /* We generated some data */
};

CaEncoder *ca_encoder_new(void);
CaEncoder *ca_encoder_unref(CaEncoder *e);

int ca_encoder_set_feature_flags(CaEncoder *e, uint64_t flags);
int ca_encoder_get_feature_flags(CaEncoder *e, uint64_t *ret);

/* Input: a directory tree, block device node or regular file */
int ca_encoder_set_base_fd(CaEncoder *e, int fd);

int ca_encoder_step(CaEncoder *e);

/* Output: archive stream data */
int ca_encoder_get_data(CaEncoder *e, const void **ret, size_t *ret_size);

int ca_encoder_current_path(CaEncoder *e, char **ret);
int ca_encoder_current_mode(CaEncoder *d, mode_t *ret);
int ca_encoder_current_payload_offset(CaEncoder *e, uint64_t *ret);
int ca_encoder_current_archive_offset(CaEncoder *e, uint64_t *ret);

#endif
