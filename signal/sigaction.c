#include <unistd.h>
#include <signal.h>
#include <stdio.h>
void printsigset(const sigset_t *set)
{
    int i=0;
    for (i=1;i<=64;i++){
        if (i==3) putchar(' ');
        if (sigismember(set,i)==1)
            putchar('1');
        else
            putchar('0');
    }
    puts("");
}

void handler(int sig)
{
    if(sig==SIGTSTP)    printf("hello SIGTSTP\n");
    if(sig==SIGINT)     printf("hello SIGINT\n");
    sleep(5);
    sigset_t st;
    sigpending(&st);
    printsigset(&st);
}

int main()
{
    printf("i m %d\n",getpid());
    struct sigaction act,oldact;
    act.sa_handler = handler;

    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask,SIGINT);
    act.sa_flags=0;
    sigprocmask(SIG_BLOCK,&act.sa_mask,NULL);

    sigaction(SIGTSTP,&act,&oldact);
    sigaction(SIGINT,&act,&oldact);
    while(1){
        write(STDOUT_FILENO,".",1);
        pause();
    }
}


