#define _DEFAULT_SOURCE

#include "secure_memory.h"

#if defined(__GLIBC__)
#include <features.h>
#endif

#include <string.h>

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
#define SECURE_MEMORY_HAVE_EXPLICIT_BZERO 1
#endif
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(__APPLE__)
#define SECURE_MEMORY_HAVE_EXPLICIT_BZERO 1
#endif

void secure_clear(void *buffer, size_t length)
{
    if (buffer == NULL || length == 0u) {
        return;
    }

#if defined(SECURE_MEMORY_HAVE_EXPLICIT_BZERO)
    explicit_bzero(buffer, length);
#else
    volatile unsigned char *cursor = (volatile unsigned char *)buffer;

    while (length > 0u) {
        *cursor = 0u;
        cursor++;
        length--;
    }
#endif
}
