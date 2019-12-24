#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
void printBlock() {
    sigset_t block;
    sigprocmask(SIG_BLOCK, NULL, &block);
    printf("block:");
    if (sigismember(&block, SIGQUIT)) printf("SIGQUIT, ");
    if (sigismember(&block, SIGALRM)) printf("SIGALRM\t");
    puts("");
} 
void handler(int sig) {
    if (sig == SIGQUIT) printf("SIGQUIT, ");
    if (sig == SIGALRM) printf("SIGALRM, ");
    printBlock();
    sleep(10);
    puts("--------------------------------------------------");
}
int main() {
    printf("I'm %d\n", getpid());
    signal(SIGQUIT, handler);
    signal(SIGALRM, handler);
    printf("before signal, ");
    printBlock();
    while(1) {
        pause();
    }
    return 0;
}
