#include <libgen.h>

#include "zlog.h"

#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

#define MAX_BUF_SIZE 8192

int get_file_size(FILE* fd);
char* read_file(const char* filename, int* size_of_shellcode);
void hexdump_shellcode(const void* data, size_t size);

pid_t findProcessByName(char* processName);
long freespaceaddr(pid_t pid);
long getlibaddr(pid_t pid, char* libname);
int checkloaded(pid_t pid, char* libname);
long getFunctionAddress(char* funcName, char* libname);
unsigned char* findRet(void* endAddr);
