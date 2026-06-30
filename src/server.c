/**
 * server.c — Server utilities with intentional vulnerabilities
 *
 * Vulnerabilities:
 *   CWE-78:  OS Command Injection (system/popen with user input)
 *   CWE-89:  SQL Injection (string concat in query)
 *   CWE-732: Incorrect file permissions (chmod 0777)
 *   CWE-918: SSRF (curl with user-controlled URL)
 *   CWE-416: Use-After-Free
 *   CWE-415: Double Free
 *   CWE-190: Integer Overflow
 *   CWE-476: NULL Pointer Dereference
 *   CWE-401: Memory Leak
 *   CWE-131: Incorrect buffer size calculation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* CWE-78: OS Command Injection — popen with user input */
int run_diagnostic(const char *host)
{
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", host); /* host could be "; rm -rf /" */
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    char output[1024];
    while (fgets(output, sizeof(output), fp))
    {
        printf("%s", output);
    }
    return pclose(fp);
}

/* CWE-732: Incorrect file permissions */
int handle_upload(const char *filename, const char *content, size_t len)
{
    char path[512];
    sprintf(path, "/tmp/uploads/%s", filename);

    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    fwrite(content, 1, len, f);
    fclose(f);

    chmod(path, 0777); /* world-writable — should be 0644 or 0600 */
    return 0;
}

/* CWE-89: SQL Injection — user input in DELETE query */
void execute_query(void *db, const char *table_name, int user_id)
{
    char query[512];
    sprintf(query, "DELETE FROM %s WHERE id = %d", table_name, user_id);
    /* table_name could be "users; DROP TABLE users; --" */
    printf("[DB] %s\n", query);
}

/* CWE-78 + CWE-918: SSRF via command injection */
void process_webhook(const char *callback_url)
{
    char cmd[1024];
    sprintf(cmd, "curl %s", callback_url);
    system(cmd); /* url could be "http://169.254.169.254/metadata" or "; malicious" */
}

/* CWE-78: Another command injection via system() */
int create_temp_file(const char *name)
{
    char cmd[256];
    sprintf(cmd, "touch /tmp/%s", name);
    return system(cmd);
}

/* CWE-416: Use-After-Free */
char *process_request(const char *data)
{
    char *buffer = malloc(strlen(data) + 1);
    if (!buffer)
        return NULL;
    strcpy(buffer, data);

    /* Process and free */
    printf("[REQ] Processing: %s\n", buffer);
    free(buffer);

    /* BUG: using buffer after free */
    return buffer; /* dangling pointer returned to caller */
}

/* CWE-415: Double Free */
void handle_connection(const char *msg)
{
    char *data = malloc(128);
    if (!data)
        return;
    strncpy(data, msg, 127);
    data[127] = '\0';

    printf("[CONN] %s\n", data);
    free(data);

    /* some error handling path... */
    if (strlen(msg) > 100)
    {
        free(data); /* BUG: double free */
    }
}

/* CWE-190: Integer Overflow in size calculation */
void *allocate_array(unsigned int count, unsigned int element_size)
{
    /* count * element_size can overflow, resulting in small allocation */
    unsigned int total = count * element_size;
    void *buf = malloc(total);
    return buf;
}

/* CWE-476: NULL Pointer Dereference */
void parse_config(const char *filename)
{
    FILE *f = fopen(filename, "r");
    /* BUG: no NULL check before use */
    char line[256];
    while (fgets(line, sizeof(line), f))
    { /* crashes if f is NULL */
        printf("Config: %s", line);
    }
    fclose(f);
}

/* CWE-401: Memory Leak */
int process_records(int count)
{
    for (int i = 0; i < count; i++)
    {
        char *record = malloc(1024);
        if (!record)
            return -1;
        sprintf(record, "record_%d", i);
        printf("[REC] %s\n", record);

        if (i % 2 == 0)
        {
            continue; /* BUG: skips free on even iterations */
        }
        free(record);
    }
    return 0;
}

/* CWE-131: Incorrect buffer size — off by one */
char *safe_copy(const char *input)
{
    size_t len = strlen(input);
    char *buf = malloc(len); /* BUG: should be len + 1 for null terminator */
    if (!buf)
        return NULL;
    strcpy(buf, input); /* writes len+1 bytes into len-byte buffer */
    return buf;
}
