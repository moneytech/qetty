#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha256.h>
#include <utils.h>

#include <passwd.h>

// Sizes.
#define MAX_LINE_LEN       2048
#define MAX_USERS          256
#define MAX_USER_LEN       256
#define MAX_PASSWDHASH_LEN 1024
#define MAX_SHELL_LEN      256
#define MAX_FULLUSER_LEN   1024
#define MAX_HOMEDIR_LEN    1024

// /etc/passwd fields.
size_t passwd_users;
char   passwd_line[MAX_LINE_LEN];

char   passwd_user[MAX_USER_LEN][MAX_USERS];
char   passwd_hash[MAX_PASSWDHASH_LEN][MAX_USERS];
uid_t  passwd_uid[MAX_USERS];
gid_t  passwd_gid[MAX_USERS];
char   passwd_fulluser[MAX_FULLUSER_LEN][MAX_USERS];
char   passwd_homedir[MAX_HOMEDIR_LEN][MAX_USERS];
char   passwd_shell[MAX_SHELL_LEN][MAX_USERS];

void parse_passwd(void) {
    // Parse /etc/passwd.
    FILE *fp = fopen("/etc/passwd", "r");
    passwd_users  = 0;
    char **tokens = NULL;

    while (fgets(passwd_line, MAX_LINE_LEN, fp)) {
        // TODO: Check for the availability of the fields instead of harcode.
        split(passwd_line, ':', &tokens);

        // TODO: Check for the availability of the fields instead of harcode.
        // First remove the last char in tokens[6], which is a newline.
        tokens[6][strlen(tokens[6]) - 2] = '\0';

        strcpy(passwd_user[passwd_users], tokens[0]);
        strcpy(passwd_hash[passwd_users], tokens[1]);
        passwd_uid[passwd_users] = atoi(tokens[2]);
        passwd_gid[passwd_users] = atoi(tokens[3]);
        strcpy(passwd_fulluser[passwd_users], tokens[4]);
        strcpy(passwd_homedir[passwd_users],  tokens[5]);
        strcpy(passwd_shell[passwd_users],    tokens[6]);
        passwd_users += 1;

        if (passwd_users == MAX_USERS)
            break;
    }

    fclose(fp);
}

int test_passwd(char *usr, char *pw) {
    // Find the user we are searching for.
    for (size_t i = 0; i < passwd_users; i++) {
        if (!strcmp(usr, passwd_user[i])) {
            // Make the password a SHA.
            SHA256_CTX ctx;
            BYTE password[SHA256_BLOCK_SIZE];
            sha256_init(&ctx);
            sha256_update(&ctx, pw, strlen(pw));
            sha256_final(&ctx, password);

            for(size_t x = 0; x < SHA256_BLOCK_SIZE; x++)
                printf("%02x", password[x]);
            
            putchar('\n');

            printf("%s\n", passwd_hash[i]);

            // Compare the password hashes.
            if (!memcmp(password, passwd_hash[i], SHA256_BLOCK_SIZE))
                return 0;
            else
                return 1;
        }
    }

    return 1;
}

char *passwd_getshell(char *usr) {
    // Find the user we are searching for.
    for (size_t i = 0; i < passwd_users; i++) {
        if (!strcmp(usr, passwd_user[i])) {
            return passwd_shell[i];
        }
    }

    return NULL;
}

uid_t passwd_getuid(char *user) {
    // Find the user we are searching for.
    for (size_t i = 0; i < passwd_users; i++) {
        if (!strcmp(user, passwd_user[i])) {
            return passwd_uid[i];
        }
    }

    return 0;
}