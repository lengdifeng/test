#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc,char **argv)
{
	int a=10;
	pid_t pid=fork();
	if(pid>0){
		a=11;
		printf("father1: %d\n",a);
		sleep(4);
		printf("father2: %d\n",a);
	}
	else if(pid == 0){
		sleep(2);	
		printf("children1: %d\n",a);
		a=12;
		printf("children2: %d\n",a);
	}
	return 0;
}
