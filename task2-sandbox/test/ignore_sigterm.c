#include <signal.h>
#include <unistd.h>

int main(void)
{
    signal(SIGTERM, SIG_IGN);

    for (;;) {
        sleep(1);
    }
}
