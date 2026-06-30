/**
 * handler.c — Entry point for the cross-file call-graph test scenario.
 *
 * This file is DELIBERATELY clean on its own: handle_request() contains no
 * vulnerability locally. The vulnerabilities live in functions it CALLS, which
 * are defined in OTHER files (validators.c, db.c, exec.c). A per-function scan
 * of this file alone finds nothing — exactly the limitation that the
 * "SAST: Scan Call Graph" command is meant to overcome.
 *
 * Call graph (depth shown in parentheses):
 *
 *   handle_request                       (root, handler.c)
 *     ├─ parse_input                     (depth 1, validators.c)
 *     │    └─ copy_to_buffer             (depth 2, validators.c)   CWE-120
 *     ├─ lookup_user                     (depth 1, db.c)           CWE-89
 *     │    └─ build_user_query           (depth 2, db.c)           CWE-89
 *     ├─ run_report                      (depth 1, exec.c)         CWE-78
 *     │    └─ shell_exec                 (depth 2, exec.c)         CWE-78
 *     └─ audit_log                       (depth 1, exec.c)         CWE-134
 *
 * "4 calls, depth 2" — handle_request makes multiple outgoing calls, and each
 * branch goes two hops deep into other files.
 */

#include <stddef.h>

/* Forward declarations of callees defined in the other files. */
char *parse_input(const char *raw);
int   lookup_user(const char *username, void *db);
void  run_report(const char *report_name);
void  audit_log(const char *fmt);

/* CLEAN on its own — no vulnerability is detectable in this function alone.
 * Everything dangerous is one or two call hops away in another file. */
int handle_request(const char *raw, const char *username, void *db)
{
    char *clean = parse_input(raw);      /* → validators.c → copy_to_buffer */
    if (clean == NULL) {
        return -1;
    }

    int uid = lookup_user(username, db); /* → db.c → build_user_query  */

    run_report(clean);                   /* → exec.c → shell_exec       */
    audit_log(clean);                    /* → exec.c (format string)    */

    return uid;
}
