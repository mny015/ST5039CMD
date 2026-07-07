#include <stdlib.h>
#include <string.h>

int main(void)
{
    const size_t chunk_size = 1024u * 1024u;

    for (;;) {
        void *chunk = malloc(chunk_size);
        if (chunk == NULL) {
            return 1;
        }
        memset(chunk, 0xA5, chunk_size);
    }
}
