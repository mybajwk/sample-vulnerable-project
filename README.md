# Sample Vulnerable Project

Project C yang sengaja berisi berbagai vulnerability untuk testing SAST tool.
Mencakup 30+ CWE yang umum ditemukan di codebase C/C++.

## Vulnerabilities

### auth.c — Authentication & Input Handling
| CWE | Vulnerability | Line |
|-----|--------------|------|
| CWE-89 | SQL Injection (sprintf into query) | `authenticate_user()` |
| CWE-798 | Hardcoded credentials (DB_PASSWORD, API_KEY, SECRET_TOKEN) | `#define` |
| CWE-327 | Weak hash (simulated MD5 for password) | `hash_password()` |
| CWE-78 | OS Command Injection (system() with user input) | `run_admin_command()` |
| CWE-134 | Format String vulnerability (printf without format) | `log_message()` |
| CWE-120 | Buffer Overflow (strcpy without bounds check) | `copy_username()` |
| CWE-22 | Path Traversal (unsanitized filename) | `read_user_file()` |
| CWE-532 | Logging sensitive data (password in printf) | `log_login_attempt()` |
| CWE-330 | Weak random (rand() without srand) | `generate_session_token()` |
| CWE-676 | Use of dangerous function (gets) | `read_user_input()` |

### server.c — Server Utilities & Memory Management
| CWE | Vulnerability | Line |
|-----|--------------|------|
| CWE-78 | OS Command Injection (popen with user input) | `run_diagnostic()` |
| CWE-732 | Incorrect file permissions (chmod 0777) | `handle_upload()` |
| CWE-89 | SQL Injection (sprintf in DELETE) | `execute_query()` |
| CWE-918 | SSRF (curl with user-controlled URL) | `process_webhook()` |
| CWE-416 | Use-After-Free (returning freed pointer) | `process_request()` |
| CWE-415 | Double Free | `handle_connection()` |
| CWE-190 | Integer Overflow (count * size) | `allocate_array()` |
| CWE-476 | NULL Pointer Dereference (no NULL check after fopen) | `parse_config()` |
| CWE-401 | Memory Leak (malloc without free in loop) | `process_records()` |
| CWE-131 | Off-by-one buffer size (missing +1 for null) | `safe_copy()` |

### network.c — Network & Crypto Utilities
| CWE | Vulnerability | Line |
|-----|--------------|------|
| CWE-119 | Buffer Overflow (memcpy with unchecked length) | `parse_packet()` |
| CWE-125 | Out-of-Bounds Read (no index check) | `get_element()` |
| CWE-787 | Out-of-Bounds Write (no index check) | `set_element()` |
| CWE-122 | Heap-based Buffer Overflow (attacker-controlled read length) | `receive_message()` |
| CWE-362 | TOCTOU Race Condition (access then fopen) | `safe_write_file()` |
| CWE-252 | Unchecked Return Value (fopen/fread) | `process_file()` |
| CWE-457 | Use of Uninitialized Variable | `calculate_checksum()` |
| CWE-126 | Buffer Over-Read (strlen on unterminated buffer) | `validate_token()` |
| CWE-242 | Inherently dangerous function (mktemp) | `create_temp_file()` |
| CWE-121 | Stack-based Buffer Overflow (recursive strcpy) | `process_nested_data()` |
| CWE-835 | Infinite Loop (missing exit condition) | `wait_for_response()` |
| CWE-134+78 | Format String + Command Injection combined | `log_and_execute()` |

### src/callgraph/ — Cross-file Call Graph scenario (VS Code extension)

Skenario khusus untuk menguji command **`SAST: Scan Call Graph`** di extension.
`handle_request()` di `handler.c` **bersih** kalau discan sendiri — semua
vulnerability ada di fungsi yang ia **panggil**, dan callee itu didefinisikan di
**file lain**. Scan per-file biasa tidak menemukan apa-apa di `handler.c`;
call-graph scan (depth ≥ 2) menelusuri panggilan lintas file dan menemukannya.

```
handle_request                  (root — handler.c, BERSIH)
  ├─ parse_input                (depth 1 — validators.c)
  │    └─ copy_to_buffer        (depth 2 — validators.c)   CWE-120 buffer overflow
  ├─ lookup_user                (depth 1 — db.c)
  │    └─ build_user_query      (depth 2 — db.c)            CWE-89  SQL injection
  ├─ run_report                 (depth 1 — exec.c)
  │    └─ shell_exec            (depth 2 — exec.c)          CWE-78  command injection
  └─ audit_log                  (depth 1 — exec.c)          CWE-134 format string
```

| File | Fungsi | CWE | Kedalaman dari root |
|------|--------|-----|---------------------|
| validators.c | `copy_to_buffer()` | CWE-120 | 2 |
| db.c | `build_user_query()` | CWE-89 | 2 |
| exec.c | `shell_exec()` | CWE-78 | 2 |
| exec.c | `audit_log()` | CWE-134 | 1 |

**Cara uji** (butuh ekstensi C/C++ terpasang agar Call Hierarchy aktif):
1. Buka folder ini di Extension Development Host.
2. Buka `src/callgraph/handler.c`, taruh kursor di file.
3. Klik kanan → **SAST: Scan Call Graph (cross-file)** (atau Command Palette).
4. Setel kedalaman lewat `sast.callGraphDepth` (default 2). Depth 1 hanya
   menjangkau `audit_log` (CWE-134); depth 2 menjangkau semua callee.

> Catatan: `shell_exec` hanya dipanggil sekali di sini, tetapi BFS sudah
> men-dedup fungsi yang dijangkau lewat beberapa jalur (lihat unit test
> `call_graph.test.ts`).

## Usage

Gunakan file-file ini sebagai input untuk testing SAST:
- **Web Dashboard**: copy-paste isi file ke Manual Scan (pilih language: C)
- **VS Code Extension**: buka folder ini di Extension Development Host
- **API**: kirim via `POST /api/v1/analysis/scan` dengan `language: "c"`

## CI/CD Integration (F19–F24 / IT-03)

Repo ini sekaligus jadi **reusable GitHub Action** (`action.yml`) untuk SAST
quality gate. Pada setiap `push`/`pull_request`, file yang berubah discan ke
backend; build **gagal** bila ada finding di atas ambang severity.

### Pakai di repo lain

```yaml
# .github/workflows/sast.yml
name: SAST Scan
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }      # butuh history untuk diff
      - uses: mybajwk/sample-vulnerable-project@v1   # ganti dgn owner/repo Action
        with:
          api-url: ${{ secrets.SAST_API_URL }}   # base URL backend
          token:   ${{ secrets.SAST_TOKEN }}     # token `sast_…` user ci_agent
          fail-on: critical                       # critical|high|medium|low
```

### Cara kerja
1. Diff file berubah (`ACM`) terhadap base SHA (PR base / push before).
2. Tiap file (C/C++/Py/JS/TS/Java) dikirim ke `POST /api/v1/analysis/scan`
   beserta metadata commit + CI (run id, PR number, actor, run URL).
3. Finding ≥ `fail-on` → **exit 1** (gate gagal); tiap finding jadi GitHub
   annotation + tabel di step summary.
4. Bila AI service `degraded`, dikeluarkan `::warning::` (tidak silently clean).

Konfigurasi (repo → Settings → Secrets and variables → Actions):
`SAST_API_URL`, `SAST_TOKEN`. Detail skrip ada di `ci/sast-scan.sh`.
