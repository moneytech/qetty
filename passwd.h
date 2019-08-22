#pragma once

#include <unistd.h>

int   test_passwd(char*, char*);
char *passwd_getshell(char*);
uid_t passwd_getuid(char*);
