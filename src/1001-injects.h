#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <getopt.h>

#include "zlog.h"

// taken from https://github.com/gaffe23/linux-inject/
#include "injections/inject_library_dlopen.h"

#include "injections/inject_shellcode_hijack_thread.h"
#include "injections/inject_shellcode_new_thread.h"
#include "injections/inject_shellcode_new_pthread.h"
#include "injections/inject_simple_elf_dev_mem.h"

#define DEFAULT_LIB "../payloads/sample-library.so"
#define DEFAULT_SHELLCODE "../payloads/raw_shellcode.bin"
#define DEFAULT_ELF "../payloads/simple.elf"
