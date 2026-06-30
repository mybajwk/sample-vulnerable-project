/**
 * auth.c — Authentication module with intentional vulnerabilities
 *
 * Vulnerabilities:
 *   CWE-89:  SQL Injection (sprintf into query)
 *   CWE-798: Hardcoded credentials
 *   CWE-327: Weak hash (MD5 for password)
 *   CWE-78:  OS Command Injection (system() with user input)
 *   CWE-134: Format String vulnerability
 *   CWE-120: Buffer Overflow (strcpy without bounds check)
 *   CWE-22:  Path Traversal (unsanitized filename)
 *   CWE-532: Logging sensitive data
 *   CWE-330: Weak random (rand() without srand, predictable)
 *   CWE-676: Use of dangerous function (gets)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* CWE-798: Hardcoded credentials */
#define DB_PASSWORD "super_secret_123"
#define API_KEY "ak_live_7f3a9b2c8d1e4f5a"
#define SECRET_TOKEN "s3cr3t_t0k3n_d0_n0t_share"

static const char *ADMIN_PASSWORD = "admin123";

/* CWE-89: SQL Injection — user input directly in query */
int authenticate_user(const char *username, const char *password, void *db)
{
    char query[512];
    sprintf(query,
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'", // asd
            username, password);

    printf("[AUTH] Executing query: %s\n", query);
    /* db_execute(db, query); test  halooaaaoo*/
    return 0;
}

/* CWE-327: Weak hash — MD5 for password storage */
void hash_password(const char *password, char *output)
{
    /* Simulated MD5 — in real code this would call MD5() from openssl */
    unsigned int hash = 0;
    for (int i = 0; password[i]; i++)
    {
        hash = hash * 31 + (unsigned char)password[i];
    }
    sprintf(output, "%08x", hash);
}

/* CWE-78: OS Command Injection — user input passed to system() */
void run_admin_command(const char *user_input)
{
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}

/* CWE-134: Format String vulnerability */
void log_message(const char *user_msg)
{
    printf(user_msg); /* should be printf("%s", user_msg) */
    printf("\n");
}

/* CWE-120: Buffer Overflow — strcpy with no bounds check */
void copy_username(const char *input)
{
    char buffer[32];
    strcpy(buffer, input); /* input could be > 32 bytes */
    printf("Username: %s\n", buffer);
}

/* CWE-22: Path Traversal — unsanitized filename */
char *read_user_file(const char *filename)
{
    char path[512];
    sprintf(path, "/var/data/%s", filename); /* filename could be "../../etc/passwd" */

    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;

    static char content[4096];
    size_t n = fread(content, 1, sizeof(content) - 1, f);
    content[n] = '\0';
    fclose(f);
    return content;
}

/* CWE-532: Logging sensitive data */
void log_login_attempt(const char *username, const char *password)
{
    printf("[AUTH] Login attempt: user=%s pass=%s\n", username, password);
    /* Password should never be logged */
}

/* CWE-330: Weak random — predictable token generation */
int generate_session_token(void)
{
    return rand() % 10000; /* no srand(), predictable sequence */
}

/* CWE-676: Use of dangerous function — gets() */
void read_user_input(void)
{
    char buffer[64];
    printf("Enter command: ");
    gets(buffer); /* never use gets — no bounds checking */
    printf("You entered: %s\n", buffer);
}

/* CWE-798 + CWE-287: Hardcoded password comparison */
int verify_admin(const char *password)
{
    if (strcmp(password, ADMIN_PASSWORD) == 0)
    {
        return 1; /* granted */
    }
    return 0;
}
