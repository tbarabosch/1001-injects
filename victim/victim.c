#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

void sleepfunc()
{
	struct timespec* sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 1;
	sleeptime->tv_nsec = 0;

	printf("Sleeping forever...\n");
	while(1)
	{
	  nanosleep(sleeptime, NULL);
	}

	free(sleeptime);
}

int main()
{
  printf("PID: %i\n", getpid());
  sleepfunc();
  return 0;
}
