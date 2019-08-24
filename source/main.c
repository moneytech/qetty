#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <termios.h>
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
    // Ask for login name.
    printf("%s login: ", hostname);
    fflush(stdout);
    fgets(user, MAX_USER_LEN, stdin);
    user[strlen(user) - 1] = '\0';

    // Ask for password.
    printf("Password: ");
    fflush(stdout);

    // Turn off echo and etc.
    struct termios orig;
    tcgetattr(STDIN_FILENO, &orig);
    struct termios new = orig;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);

    fgets(password, MAX_PASSWORD_LEN, stdin);

    // Reset terminal properties.
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig);

    putchar('\n');

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
        char *shell = passwd_getshell(user);
        char *args[] = {shell, NULL};
        execvp(shell, args);
    } else {
        waitpid(pid, &status, 0);
    }
}
