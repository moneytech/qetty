#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/wait.h>
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
    fflush(stdout);
    fgets(user, MAX_USER_LEN, stdin);
    user[strlen(user) - 1] = '\0';

    printf("Password: ");
    fflush(stdout);
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

    // Prepare the info we need.
    parse_passwd();

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

    // Fork to execute the login shell.
    pid_t pid = fork();
    int status;

    if (!pid) {
        // Set the UID in the forked thread.
        uid_t uid = passwd_getuid(user);
        setuid(uid);

        // Launch!
        char *args[] = {passwd_getshell(user), NULL};
        execvp(passwd_getshell(user), args);
    } else {
        waitpid(pid, &status, 0);
    }
}
