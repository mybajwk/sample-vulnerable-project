/**
 * exec.c — Command execution + logging helpers (depth 1 + 2).
 *
 * Two branches of the call graph land here:
 *   run_report → shell_exec   (CWE-78, OS command injection, depth 2)
 *   audit_log                 (CWE-134, format string, depth 1)
 *
 * shell_exec is also reachable from run_report in db.c-style fashion, so it is
 * a shared callee — useful for checking that the BFS dedups it to one scan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* depth 2: CWE-78 — user-influenced string passed straight to system(). */
void shell_exec(const char *arg)
{
    char cmd[256];
    sprintf(cmd, "report-tool %s", arg); /* arg is attacker-controlled */
    system(cmd);                         /* OS command injection */
}

/* depth 1: forwards the report name into the shell. */
void run_report(const char *report_name)
{
    shell_exec(report_name); /* hop to CWE-78 */
}

/* depth 1: CWE-134 — user string used as the printf format directly. */
void audit_log(const char *fmt)
{
    printf(fmt); /* should be printf("%s", fmt) — format string bug */
    printf("\n");
}
