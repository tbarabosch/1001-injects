#include "1001-injects.h"

void init_logging(){
  int rc;

  rc = dzlog_init("logging.conf", "default");

  if (rc) {
      printf("init failed\n");
      exit(1);
  }
}

void deinit_logging(){
  zlog_fini();
}

void print_usage(){
  printf("Usage: linux-inject -p PID\n");
}

int main(int argc, char *argv[]){
  int option = 0;
  int pid = -1;

  while ((option = getopt(argc, argv,"p:")) != -1) {
    switch (option) {
      case 'p': pid = atoi(optarg);
	break;
    default:
      print_usage();
      return 1;    }
  }

  init_logging();

  if (pid == -1){
    dzlog_error("No victim PID defined. Exiting...");
    exit(1);
  }
  dzlog_info("Injecting to PID %i.", pid);

  printf("Choose injection method:\n");
  printf("0: inject_library_dlopen\n");
  printf("1: inject_shellcode_hijack_thread\n");
  printf("2: inject_shellcode_new_thread\n");
  printf("3: inject_shellcode_new_pthread\n");
  printf("4: inject_simple_elf_dev_mem\n");
  int method;
  scanf ("%d",&method);
  
  switch(method) {
  case 0: 
    inject_library_dlopen(pid, DEFAULT_LIB);
    break;
  case 1:
   inject_shellcode_hijack_thread(pid, DEFAULT_SHELLCODE);
   break;
  case 2:
    inject_shellcode_new_thread(pid, DEFAULT_SHELLCODE);
    break;
  case 3:
    inject_shellcode_new_pthread(pid, DEFAULT_SHELLCODE);
    break;
  case 4:
    inject_simple_elf_dev_mem(pid, DEFAULT_ELF);
    break;
  default:
    printf("Please choose an available method!\n");
    exit(1);
  }
  
  deinit_logging();
  
  return 0;
}
