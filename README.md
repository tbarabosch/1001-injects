# Thousand and one injects (1001-injects)

There many ways to inject code into another process. This project poses a collection of new and old code injection techniques on Linux systems.
It's a proof of concept/small research project that helped me learn more about code injections on Linux. Though the code is rather hackish it might help other folks, who wish to do similar stuff.
Note that this is stuff that your normal debugger like gdb would also do (e.g. using the syscall ptrace). You must be root to carry out the injections. 

I borrowed some code from other cool projects. Where this happen, I left a link to give the original author credit. Projects that I found especially useful are

* [linux-inject](https://github.com/gaffe23/linux-inject) by gaffe23
* [linux-injector](https://github.com/dismantl/linux-injector) by dismantl

# Running the Proof of Concepts

First, you may need to execute the script scripts/insecure_system.sh to carry out the injections. Then, you have to build the payloads with the script payloads/build_payloads.sh. Though, you should be able to define your own. For testing purposes, use the victim program. Finally, compile 1001-injects by executing its make file. There is only one requirement: [zlog](https://github.com/HardySimpson/zlog).

Start the victim program

``` bash
./victim.elf 
PID: 2885
Sleeping forever...
```
Run 1001-injects, passing it the victim PID

``` bash
sudo ./1001-injects.elf -p 2885
2017-07-01 21:13:10 INFO [2899:1001-injects.c:41] Injecting to PID 2885.
Choose injection method:
0: inject_library_dlopen
1: inject_shellcode_hijack_thread
2: inject_shellcode_new_thread
3: inject_shellcode_new_pthread
4: inject_simple_elf_dev_mem
1
2017-07-01 21:13:13 INFO [2899:injections/inject_shellcode_hijack_thread.c:5] Loading shellcode from ../payloads/raw_shellcode.bin
2017-07-01 21:13:13 DEBUG [2899:utils.c:13] Shellcode dump:
90 90 90 90 90 5A EB 14  48 31 C0 B0 01 48 89 C7  |  .....Z..H1...H.. 
5E 48 31 D2 48 83 C2 0F  0F 05 EB FE E8 E7 FF FF  |  ^H1.H........... 
FF 49 6E 6A 65 63 74 65  64 21 0D 0A              |  .Injected!.. 
2017-07-01 21:13:13 DEBUG [2899:ptrace.c:25] Attaching to PID 2885
2017-07-01 21:13:13 DEBUG [2899:ptrace.c:80] Getting registers of PID 2885
2017-07-01 21:13:13 DEBUG [2899:ptrace.c:145] Setting registers of PID 2885
2017-07-01 21:13:13 DEBUG [2899:ptrace.c:231] Writing 44 bytes to 0x400008 in PID 2885
2017-07-01 21:13:13 DEBUG [2899:ptrace.c:89] Continuing PID 2885
2017-07-01 21:13:13 INFO [2899:injections/inject_shellcode_hijack_thread.c:30] Finished shellcode injection into PID 2885
```
The payload should have been executed within the victim process

``` bash
PID: 2885
Sleeping forever...
Injected!
```

