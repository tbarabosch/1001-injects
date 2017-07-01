#include <stdio.h>
#include <dlfcn.h>

void on_inject()
{
	printf("Injected\n");
}

__attribute__((constructor))
void loadMsg()
{
	on_inject();
}
