#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <wait.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/user.h>

#include "linux/types.h"

#include "zlog.h"

#include "../utils.h"
#include "../ptrace.h"

void inject_shellcode_new_pthread(pid_t target, char* path_to_shellcode);
