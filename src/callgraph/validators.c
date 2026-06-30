/**
 * validators.c — Input "validation" helpers (depth 1 + 2 from handle_request).
 *
 * parse_input looks harmless; the real bug is in copy_to_buffer, one more hop
 * down. A call-graph scan at depth >= 2 reaches it.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* depth 2: CWE-120 — strcpy into a fixed stack buffer with no bounds check. */
char *copy_to_buffer(const char *input)
{
    static char buffer[32];
    strcpy(buffer, input); /* input may exceed 32 bytes → stack overflow */
    return buffer;
}

/* depth 1: looks like a validator, but just forwards to the vulnerable copy. */
char *parse_input(const char *raw)
{
    if (raw == NULL) {
        return NULL;
    }
    return copy_to_buffer(raw); /* one hop to the actual CWE-120 */
}
