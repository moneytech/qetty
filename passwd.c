#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sha256.h>
#include <passwd.h>

// Sizes.
#define MAX_USER_LEN       256
#define MAX_PASSWDHASH_LEN 1024
#define MAX_SHELL_LEN      256
#define MAX_FULLUSER_LEN   1024
#define MAX_HOMEDIR_LEN    1024

// /etc/passwd fields.
char  passwd_user[MAX_USER_LEN];
char  passwd_hash[MAX_PASSWDHASH_LEN];
uid_t passwd_uid;
gid_t passwd_gid;
char  passwd_fulluser[MAX_FULLUSER_LEN];
char  passwd_homedir[MAX_HOMEDIR_LEN];
char  passwd_shell[MAX_SHELL_LEN];

int test_passwd(char *user, char *pw) {
    // Hash the passed password.
    SHA256_CTX ctx;
    BYTE password[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, pw, strlen(pw));
    sha256_final(&ctx, password);

    for (int x = 0; x < SHA256_BLOCK_SIZE; x++)
        printf("%02x", password[x]);
    
    printf("\n");

    // Open file for testing.
    FILE *fp = fopen("/etc/passwd", "r");

    while (!feof(fp)) {
        // Get fields.
        fscanf(fp, "%s:%s:%u:%u:%s:%s:%s", passwd_user, passwd_hash,
            &passwd_uid, &passwd_gid, passwd_fulluser, passwd_homedir,
            passwd_shell);

        // Check the user, if its correct, check password.
        if (!strcmp(user, passwd_user)) {
            if (!memcmp(password, passwd_hash, SHA256_BLOCK_SIZE)) {
                return 0;
            }
        } 
    }

    fclose(fp);
    return -1;
}
