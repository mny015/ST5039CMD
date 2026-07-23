#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHUNK_SIZE (1024u * 1024u)
#define MAXIMUM_CHUNKS 64u
#define ALLOCATION_DELAY_NANOSECONDS 20000000L

int main(void)
{
    void *chunks[MAXIMUM_CHUNKS];
    struct timespec delay;
    size_t chunk_index;

    memset(chunks, 0, sizeof(chunks));
    delay.tv_sec = 0;
    delay.tv_nsec = ALLOCATION_DELAY_NANOSECONDS;

    puts("memory_hog: allocating gradually up to a safe 64 MiB cap");
    for (chunk_index = 0u; chunk_index < MAXIMUM_CHUNKS; chunk_index++) {
        chunks[chunk_index] = malloc(CHUNK_SIZE);
        if (chunks[chunk_index] == NULL) {
            fputs("memory_hog: allocation failed\n", stderr);
            return EXIT_FAILURE;
        }

        memset(chunks[chunk_index], 0xA5, CHUNK_SIZE);
        if ((chunk_index + 1u) % 8u == 0u) {
            printf("memory_hog: allocated %lu MiB\n",
                   (unsigned long)(chunk_index + 1u));
            fflush(stdout);
        }
        (void)nanosleep(&delay, NULL);
    }

    puts("memory_hog: allocation cap reached; holding memory");
    for (;;) {
        delay.tv_sec = 1;
        delay.tv_nsec = 0;
        (void)nanosleep(&delay, NULL);
    }
}
