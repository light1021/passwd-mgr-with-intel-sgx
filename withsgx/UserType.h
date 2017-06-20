#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <sgx_error.h>
#include "sgx_eid.h"     /* sgx_enclave_id_t */
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif


# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"


extern sgx_enclave_id_t global_eid;    /* global enclave id */

typedef struct {
    #define BUFLEN 16
    uint32_t version;
    unsigned char master_pass[BUFLEN];
} HEADER;

typedef struct {
    unsigned char site[BUFLEN * 2];
    unsigned char user[BUFLEN];
    unsigned char pass[BUFLEN];
} ENTRY;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;
