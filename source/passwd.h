#pragma once

#include <unistd.h>

void  parse_passwd(void);
int   test_passwd(char *usr, char *pw);
char *passwd_getshell(char*);
uid_t passwd_getuid(char*);
