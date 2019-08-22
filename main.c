#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/utsname.h>

#include <passwd.h>

#define MAX_USER_LEN     256
#define MAX_PASSWORD_LEN 1024
#define MAX_HOSTNAME_LEN 1024
#define MAX_PASSWD_LEN   1024

// Input fields.
char user[MAX_USER_LEN];
char password[MAX_PASSWORD_LEN];
char hostname[MAX_HOSTNAME_LEN];

void set_global_data(void) {
    printf("%s login: ", hostname);
    fgets(user, MAX_USER_LEN, stdin);
    user[strlen(user) - 1] = '\0';

    printf("Password: ");
    fgets(password, MAX_PASSWORD_LEN, stdin);
    password[strlen(password) - 1] = '\0';
}

int main(void) {
    // OS and hostname detection.
    struct utsname buffer;
    uname(&buffer);
    gethostname(hostname, MAX_HOSTNAME_LEN);
    printf("%s (%s) (%s)\n\n", buffer.sysname, hostname,
        basename(ttyname(STDIN_FILENO)));

    while (1) {
        // Get command line user and password.
        set_global_data();

        // Test against /etc/passwd.
        if (test_passwd(user, password)) {
            printf("Login incorrect.\n\n");
        } else {
            break;
        }
    }
}
