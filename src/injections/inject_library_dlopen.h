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

#include "../utils.h"
#include "../ptrace.h"

#include "zlog.h"

void inject_library_dlopen(pid_t target, char* libname);
