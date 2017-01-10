#ifndef foocadecoderhfoo
#define foocadecoderhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct CaDecoder CaDecoder;

enum {
        CA_DECODER_FINISHED,   /* The end of the stream has been reached */
        CA_DECODER_STEP,       /* We processed a bit, call us again */
        CA_DECODER_REQUEST,    /* We need more data */
        CA_DECODER_NEXT_FILE,  /* We started processing a new file */
        CA_DECODER_PAYLOAD,    /* We have some payload data for you */
};

CaDecoder *ca_decoder_new(void);
CaDecoder *ca_decoder_unref(CaDecoder *d);

int ca_decoder_get_feature_flags(CaDecoder *d, uint64_t *ret);

/* Output: a file descriptor to a directory tree, block device node, or regular file */
int ca_decoder_set_base_fd(CaDecoder *d, int fd);

/* Output: if no output to the file system is desired: specbify instead what kind of object is to be read */
int ca_decoder_set_base_mode(CaDecoder *d, mode_t mode);

int ca_decoder_step(CaDecoder *d);

/* If ca_decoder_step() returned CA_DECODER_REQUEST, which offset it desired now */
int ca_decoder_get_request_offset(CaDecoder *d, uint64_t *offset);

/* Input: archive stream data */
int ca_decoder_put_data(CaDecoder *d, const void *p, size_t size);
int ca_decoder_put_data_fd(CaDecoder *d, int fd, uint64_t offset, uint64_t size);
int ca_decoder_put_eof(CaDecoder *d);

/* Output: payload data */
int ca_decoder_get_payload(CaDecoder *d, const void **ret, size_t *ret_size);

int ca_decoder_current_path(CaDecoder *d, char **ret);
int ca_decoder_current_mode(CaDecoder *d, mode_t *ret);
int ca_decoder_current_offset(CaDecoder *d, uint64_t *ret);

#endif
