#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    signal(SIGTERM, SIG_IGN);
    puts("ignore_sigterm: SIGTERM ignored; waiting for sandbox escalation");

    for (;;) {
        sleep(1);
    }
}
