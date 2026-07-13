#include <stdio.h>

int main(void)
{
    volatile unsigned long counter = 0u;

    puts("infinite_loop: consuming CPU until the sandbox stops me");
    for (;;) {
        counter++;
    }
}
