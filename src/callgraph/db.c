/**
 * db.c — Database access helpers (depth 1 + 2 from handle_request).
 *
 * lookup_user delegates query construction to build_user_query, where the
 * SQL injection actually lives (CWE-89).
 */

#include <stdio.h>
#include <string.h>

/* depth 2: CWE-89 — username concatenated straight into the SQL string. */
void build_user_query(char *out, size_t out_size, const char *username)
{
    /* No parameterization / escaping — classic SQL injection. */
    snprintf(out, out_size,
             "SELECT id FROM users WHERE username = '%s'", username);
}

/* depth 1: builds the injectable query, then "executes" it. */
int lookup_user(const char *username, void *db)
{
    char query[512];
    build_user_query(query, sizeof(query), username); /* hop to CWE-89 */

    printf("[DB] %s\n", query);
    /* db_exec(db, query); */
    (void)db;
    return 0;
}
