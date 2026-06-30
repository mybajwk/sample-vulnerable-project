/**
 * network.c — Network and crypto utilities with intentional vulnerabilities
 *
 * Vulnerabilities:
 *   CWE-119: Buffer Overflow (memcpy with unchecked length)
 *   CWE-125: Out-of-Bounds Read
 *   CWE-787: Out-of-Bounds Write
 *   CWE-362: Race Condition (TOCTOU)
 *   CWE-252: Unchecked Return Value
 *   CWE-457: Use of Uninitialized Variable
 *   CWE-126: Buffer Over-Read (strlen on unterminated buffer)
 *   CWE-122: Heap-based Buffer Overflow
 *   CWE-367: TOCTOU Race Condition (access then open)
 *   CWE-242: Use of inherently dangerous function (mktemp)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>


/* CWE-119: Buffer Overflow via memcpy — unchecked length */
void parse_packet(const char *packet, size_t packet_len) {
    char header[16];
    /* BUG: packet_len could be > 16, overflowing header */
    memcpy(header, packet, packet_len);
    printf("[NET] Header: %.16s\n", header);
}


/* CWE-125: Out-of-Bounds Read */
int get_element(int *array, int size, int index) {
    /* BUG: no bounds check on index */
    return array[index];  /* index could be negative or >= size */
}


/* CWE-787: Out-of-Bounds Write */
void set_element(int *array, int size, int index, int value) {
    /* BUG: no bounds check */
    array[index] = value;  /* arbitrary write if index is out of bounds */
}


/* CWE-122: Heap-based Buffer Overflow */
char *receive_message(int socket_fd) {
    char length_buf[4];
    read(socket_fd, length_buf, 4);
    int msg_len = *(int *)length_buf;  /* attacker-controlled length */

    char *buffer = malloc(256);
    if (!buffer) return NULL;

    /* BUG: reads msg_len bytes into 256-byte buffer */
    read(socket_fd, buffer, msg_len);
    buffer[msg_len] = '\0';  /* also potential OOB write */
    return buffer;
}


/* CWE-362 + CWE-367: TOCTOU Race Condition */
int safe_write_file(const char *path, const char *data) {
    /* Check if file exists */
    if (access(path, F_OK) == 0) {
        printf("[FS] File already exists: %s\n", path);
        return -1;
    }

    /* BUG: Race window — file could be created between access() and fopen() */
    /* An attacker could symlink path to /etc/passwd in this window */
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s", data);
    fclose(f);
    return 0;
}


/* CWE-252: Unchecked Return Value */
void process_file(const char *path) {
    FILE *f = fopen(path, "r");
    /* BUG: f could be NULL, but we don't check */

    char buf[1024];
    fread(buf, 1, 1024, f);  /* crash if f is NULL */

    /* BUG: return value of fread not checked — buf may be partially filled */
    printf("[FILE] Content: %s\n", buf);
    fclose(f);
}


/* CWE-457: Use of Uninitialized Variable */
int calculate_checksum(const char *data, int len) {
    int checksum;  /* BUG: not initialized to 0 */
    for (int i = 0; i < len; i++) {
        checksum += (unsigned char)data[i];
    }
    return checksum;
}


/* CWE-126: Buffer Over-Read — strlen on potentially unterminated data */
int validate_token(const char *raw_data, size_t data_len) {
    char token[64];
    memcpy(token, raw_data, data_len);
    /* BUG: if data_len == 64, token is not null-terminated */

    size_t token_len = strlen(token);  /* reads past buffer boundary */
    return token_len > 0 ? 1 : 0;
}


/* CWE-242: Inherently dangerous function — mktemp */
char *create_temp_file(void) {
    char template[] = "/tmp/sast_XXXXXX";
    mktemp(template);  /* BUG: mktemp is unsafe — use mkstemp instead */

    FILE *f = fopen(template, "w");
    if (f) {
        fprintf(f, "temp data\n");
        fclose(f);
    }
    return strdup(template);
}


/* CWE-134 + CWE-78: Combined format string + command injection */
void log_and_execute(const char *user_action) {
    char log_msg[512];
    sprintf(log_msg, user_action);  /* format string vulnerability */

    char cmd[1024];
    sprintf(cmd, "echo '%s' >> /var/log/actions.log", log_msg);
    system(cmd);  /* command injection via log_msg */
}


/* CWE-121: Stack-based Buffer Overflow via recursive call */
void process_nested_data(const char *data, int depth) {
    char local_buf[128];
    strcpy(local_buf, data);

    if (depth > 0) {
        /* BUG: unbounded recursion with large stack allocation each frame */
        process_nested_data(data, depth - 1);
    }
    printf("[NEST:%d] %s\n", depth, local_buf);
}


/* CWE-835: Infinite Loop — missing break condition */
void wait_for_response(int socket_fd) {
    char buf[256];
    int status = 0;

    while (status == 0) {
        int n = read(socket_fd, buf, sizeof(buf));
        /* BUG: if read returns 0 (EOF) or -1 (error), loop never exits */
        if (n > 0 && buf[0] == 'O' && buf[1] == 'K') {
            status = 1;
        }
    }
}
