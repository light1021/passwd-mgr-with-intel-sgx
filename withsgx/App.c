#include "UserType.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;



/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

void printdata(uint8_t *data){
    printf("%s\n", data);
}

void read_rand(uint32_t *seed, uint32_t * rand_val){
    
    srand(*seed);
    *rand_val = rand();
}

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);

        if (fp != NULL) fclose(fp);
        return -1;
    }
    printf("SGX_SUCCESS created Enclave\n");
    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

enum
{
    SITE,
    USER,
    PASS
};

char * const add_opts[] =
{
    [SITE] = "site",
    [USER] = "username",
    [PASS] = "password",
    NULL
};

static struct option longopts[] =
{
    { "help", no_argument,       0, 'h' },
    { "show", no_argument,       0, 's' },
    { "init", no_argument,       0, 'i' },
    { "add",  required_argument, 0, 'a' },
    { 0,      0,                 0,  0  }
};


void help()
{
    fprintf(stderr,
        "\nMilitary-Grade Password Manager\n"
        "Usage: ./passwd_mgr [options] [suboptions] <database>\n\n"
        "--init\n"
        "\tInitialize a new database.\n\n"
        "--show\n"
        "\tShow all passwords in a database.\n\n"
        "--add site=X,username=Y,password=Z\n"
        "\tAdd a password to the database.\n\n"
    );
}


int init(char *db)
{
    HEADER hdr;
    FILE *dbh;

    if ((dbh = fopen(db, "w")) == NULL)
        return errno;

    #define VERSION 1297106765
    hdr.version = VERSION;

    while (1)
    {
        size_t len = BUFLEN;
        unsigned char *master, *verify;

        master = (unsigned char *) getpass("Select master password  : ");

        if (strlen((char *) master) < BUFLEN)
            len = strlen((char *) master);

        memset(&hdr.master_pass, 0, sizeof(hdr.master_pass));
        memcpy(&hdr.master_pass, master, len);

        verify = (unsigned char *) getpass("Confirm master password : ");

        if (strlen((char *) verify) == len &&
            memcmp(hdr.master_pass, verify, len) == 0
           ) break;

        printf("\nPasswords do not match!\n\n");
        sleep(1);
    }

    encrypt_masterpwd(global_eid, hdr.master_pass, BUFLEN);

    fwrite(&hdr, sizeof(hdr), 1, dbh);
    fclose(dbh);

    return 0;
}

int show(char *db)
{

    HEADER hdr;
    ENTRY entry;
    FILE *dbh;
    int count = 0;
    int ret_val=0;

    if ((dbh = fopen(db, "r")) == NULL)
        return errno;

    fread(&hdr, sizeof(hdr), 1, dbh);
    printf("%s\n", hdr.master_pass);

    while (1)
    {
        unsigned char *master = (unsigned char *) getpass("Enter master password : ");
        

        verify_pwd(global_eid, &ret_val, master, hdr.master_pass, strlen(master));
        if (ret_val) break;

        //encrypt_data(hdr.master_pass, BUFLEN);

        printf("\nIncorrect password!\n\n");
        sleep(1);

        if (++count == 3) return EACCES;
    }

    printf("\n%-32s\t%-16s\t%-16s\n", "SITE", "USERNAME", "PASSWORD");
    printf("--------------------------------");
    printf("--------------------------------");
    printf("----------------\n");

    while (!feof(dbh) && fread(&entry, sizeof(entry), 1, dbh) == 1)
    {
        encrypt_data(global_eid, entry.site, sizeof(entry.site));
        encrypt_data(global_eid, entry.user, sizeof(entry.user));
        encrypt_data(global_eid, entry.pass, sizeof(entry.pass));

        printf("%-32s\t%-16s\t%-16s\n", entry.site, entry.user, entry.pass);
    }

    printf ("\n");

    fclose(dbh);

    return 0;
}

int add(char *db, char *site, char *user, char *pass)
{

    HEADER hdr;
    ENTRY entry;
    FILE *dbh;
    int count = 0;
    int ret_val = 0;
    size_t len = BUFSIZ;

    if ((dbh = fopen(db, "r")) == NULL)
        return errno;

    fread(&hdr, sizeof(hdr), 1, dbh);
    fclose(dbh);

    while (1)
    {
        unsigned char *master = (unsigned char *) getpass("Enter master password : ");

        verify_pwd(global_eid, &ret_val, master, hdr.master_pass, strlen(master));
        if (ret_val) break;

        //encrypt_data(hdr.master_pass, BUFLEN);

        printf("\nIncorrect password!\n\n");
        sleep(1);

        if (++count == 3) return EACCES;
    }

    len = strlen(site);
    if (len > BUFLEN * 2 - 1)
        len = BUFLEN * 2 - 1;

    memset(&entry.site, 0, BUFLEN * 2);
    memcpy(&entry.site, site, len);

    encrypt_data(global_eid, entry.site, BUFLEN * 2);

    len = strlen(user);
    if (len > BUFLEN - 1)
        len = BUFLEN - 1;

    memset(&entry.user, 0, BUFLEN);
    memcpy(&entry.user, user, len);

    encrypt_data(global_eid, entry.user, BUFLEN);

    len = strlen(pass);
    if (len > BUFLEN - 1)
        len = BUFLEN - 1;

    memset(&entry.pass, 0, BUFLEN);
    memcpy(&entry.pass, pass, len);

    encrypt_data(global_eid, entry.pass, BUFLEN);

    if ((dbh = fopen(db, "a+")) == NULL)
        return errno;

    fwrite(&entry, sizeof(entry), 1, dbh);
    fclose(dbh);

    return 0;
}


int main(int argc, char **argv)
{
    char *db = NULL, *site = NULL, *user = NULL, *pass = NULL;
    char *subopt, *value;

    int opts = 0, idx = 0, ret = 0;
    int _init = 0, _show = 0, _add = 0;

    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    while (1)
    {
        if ((opts = getopt_long_only(argc, argv, "", longopts, &idx)) == -1)
            break;

        switch (opts)
        {
            case 0:

                if (longopts[idx].flag)
                    break;

            case 'h':

                help();
                return 0;

            case 'i':

                _init++;
                break;

            case 's':

                _show++;
                break;

            case 'a':

                _add++;
                subopt = optarg;

                while (*subopt != '\0')
                {
                    switch (getsubopt(&subopt, add_opts, &value))
                    {
                        case SITE:
                            site = strdup(value);
                            break;
                        case USER:
                            user = strdup(value);
                            break;
                        case PASS:
                            pass = strdup(value);
                            break;
                        default:
                            fprintf(stderr, "Error: unknown option\n");
                            return -1;
                    }
                }

                break;

            default:
                abort();
        }
    }

    if (optind == argc)
    {
        fprintf(stderr, "Error: database required\n");

        sgx_destroy_enclave(global_eid);
        return -1;
    }

    assert(db = strdup(argv[optind]));

    if (_init)
    {
        if ((ret = init(db)) != 0)
            fprintf(stderr, "Error: %s\n", strerror(ret));
        sgx_destroy_enclave(global_eid);
        return ret;
    }

    if (_show)
    {
        if ((ret = show(db)) != 0)
            fprintf(stderr, "Error: %s\n", strerror(ret));
        sgx_destroy_enclave(global_eid);
        return ret;
    }

    if (_add)
    {
        assert(site != NULL);
        assert(user != NULL);
        assert(pass != NULL);

        if ((ret = add(db, site, user, pass)) != 0)
            fprintf(stderr, "Error: %s\n", strerror(ret));
        sgx_destroy_enclave(global_eid);
        return ret;
    }
    sgx_destroy_enclave(global_eid);
    return -1;
}
