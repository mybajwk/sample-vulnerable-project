#!/usr/bin/env bash
# SAST CI quality gate (F19–F24 / IT-03).
#
# Scans the files changed in this push/PR against the SAST backend and fails
# the pipeline when findings at or above the threshold severity are detected.
#
# Required environment:
#   SAST_API_URL    e.g. https://sast.example.com  (no trailing slash)
#   SAST_TOKEN      a `sast_…` API token for a ci_agent user (repo secret!)
# Optional:
#   FAIL_ON         critical|high|medium|low   (default: critical)
#   BASE_SHA        diff base (default: HEAD~1; in PRs pass the target branch sha)
#
# GitHub-provided (picked up automatically when present):
#   GITHUB_SHA GITHUB_ACTOR GITHUB_RUN_ID GITHUB_JOB GITHUB_REF_NAME
#   GITHUB_EVENT_NAME GITHUB_SERVER_URL GITHUB_REPOSITORY GITHUB_STEP_SUMMARY

set -euo pipefail

: "${SAST_API_URL:?SAST_API_URL is required}"
: "${SAST_TOKEN:?SAST_TOKEN is required}"
FAIL_ON="${FAIL_ON:-critical}"
BASE_SHA="${BASE_SHA:-HEAD~1}"

# Strip a trailing slash so "$SAST_API_URL/api/…" never doubles the slash.
SAST_API_URL="${SAST_API_URL%/}"

# Validate the diff base. GitHub sends `github.event.before` as all-zeros on a
# branch's first push, and after force-pushes/history rewrites the SHA may not
# exist in this clone at all — either would make `git diff` die under `set -e`.
# Fall back to HEAD~1, and to the empty tree on a single-commit repo.
if [ -z "$BASE_SHA" ] \
   || [ "$BASE_SHA" = "0000000000000000000000000000000000000000" ] \
   || ! git cat-file -e "$BASE_SHA^{commit}" 2>/dev/null; then
  if git rev-parse -q --verify "HEAD~1^{commit}" >/dev/null 2>&1; then
    echo "::notice::diff base '$BASE_SHA' unavailable — falling back to HEAD~1"
    BASE_SHA="HEAD~1"
  else
    echo "::notice::no parent commit — scanning all files against the empty tree"
    BASE_SHA=$(git hash-object -t tree /dev/null)
  fi
fi

# Severity ranking for the quality gate.
rank() {
  case "$1" in
    critical) echo 4 ;;
    high)     echo 3 ;;
    medium)   echo 2 ;;
    low)      echo 1 ;;
    *)        echo 0 ;;
  esac
}
THRESHOLD=$(rank "$FAIL_ON")

# Map file extension → language id the backend understands.
lang_for() {
  case "$1" in
    *.py)            echo python ;;
    *.js)            echo javascript ;;
    *.ts|*.tsx)      echo typescript ;;
    *.java)          echo java ;;
    *.c|*.h)         echo c ;;
    *.cpp|*.cc|*.hpp) echo cpp ;;
    *)               echo "" ;;
  esac
}

CHANGED=$(git diff --name-only --diff-filter=ACM "$BASE_SHA"...HEAD 2>/dev/null || git diff --name-only --diff-filter=ACM "$BASE_SHA" HEAD)

PR_NUMBER=""
if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] && [ -n "${GITHUB_REF:-}" ]; then
  PR_NUMBER=$(echo "$GITHUB_REF" | sed -n 's|refs/pull/\([0-9]*\)/.*|\1|p')
fi

COMMIT_AUTHOR_NAME=$(git log -1 --format='%an')
COMMIT_AUTHOR_EMAIL=$(git log -1 --format='%ae')
COMMIT_MESSAGE=$(git log -1 --format='%s')
REPO_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}"
RUN_URL="${REPO_URL}/actions/runs/${GITHUB_RUN_ID:-}"

TOTAL_BLOCKING=0
SUMMARY_ROWS=""
SCANNED=0

for FILE in $CHANGED; do
  [ -f "$FILE" ] || continue
  LANG=$(lang_for "$FILE")
  [ -n "$LANG" ] || continue

  echo "→ scanning $FILE ($LANG)"
  SCANNED=$((SCANNED + 1))

  # Build the request safely with jq (no string interpolation of file content).
  BODY=$(jq -n \
    --rawfile content "$FILE" \
    --arg file_path "$FILE" \
    --arg language "$LANG" \
    --arg commit_sha "${GITHUB_SHA:-}" \
    --arg project_url "$REPO_URL" \
    --arg branch "${GITHUB_REF_NAME:-}" \
    --arg commit_message "$COMMIT_MESSAGE" \
    --arg author_name "$COMMIT_AUTHOR_NAME" \
    --arg author_email "$COMMIT_AUTHOR_EMAIL" \
    --arg ci_run_id "${GITHUB_RUN_ID:-}" \
    --arg ci_job_name "${GITHUB_JOB:-}" \
    --arg pr_number "$PR_NUMBER" \
    --arg trigger_event "${GITHUB_EVENT_NAME:-push}" \
    --arg trigger_actor "${GITHUB_ACTOR:-}" \
    --arg ci_run_url "$RUN_URL" \
    '{
      file_path: $file_path, content: $content, language: $language,
      commit_sha: $commit_sha, project_url: $project_url, branch: $branch,
      commit_message: $commit_message,
      commit_author_name: $author_name, commit_author_email: $author_email,
      ci_provider: "github", ci_run_id: $ci_run_id, ci_job_name: $ci_job_name,
      trigger_event: $trigger_event, trigger_actor: $trigger_actor,
      ci_run_url: $ci_run_url
    }
    + (if $pr_number != "" then {pr_number: $pr_number} else {} end)')

  RESPONSE=$(curl -sS --fail-with-body \
    -X POST "$SAST_API_URL/api/v1/analysis/scan" \
    -H "Authorization: Bearer $SAST_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$BODY")

  STATUS=$(echo "$RESPONSE" | jq -r '.analysis_status')
  if [ "$STATUS" = "degraded" ]; then
    echo "::warning file=$FILE::AI service degraded — results may be incomplete"
  fi

  # Count findings at/above threshold; emit GitHub annotations for each finding.
  FILE_BLOCKING=$(echo "$RESPONSE" | jq --argjson t "$THRESHOLD" '
    [.sarif_output.runs[0].results[]? |
     (.properties.severity // .level) as $sev |
     ({"critical":4,"high":3,"error":3,"medium":2,"warning":2,"low":1,"note":1}[$sev] // 0) |
     select(. >= $t)] | length')
  TOTAL_BLOCKING=$((TOTAL_BLOCKING + FILE_BLOCKING))

  while IFS=$'\t' read -r line sev msg; do
    [ -n "$line" ] || continue
    echo "::warning file=$FILE,line=$line::[$sev] $msg"
    SUMMARY_ROWS="$SUMMARY_ROWS
| \`$FILE\` | $line | $sev | $msg |"
  done < <(echo "$RESPONSE" | jq -r '
    .sarif_output.runs[0].results[]? |
    [(.locations[0].physicalLocation.region.startLine // 0),
     (.properties.severity // .level), .message.text] | @tsv')
done

# Step summary table (shows up on the workflow run page).
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## SAST scan results"
    echo ""
    echo "Scanned **$SCANNED** changed file(s) · gate: fail on \`$FAIL_ON\`+"
    if [ -n "$SUMMARY_ROWS" ]; then
      echo ""
      echo "| File | Line | Severity | Finding |"
      echo "|------|------|----------|---------|"
      echo "$SUMMARY_ROWS"
    else
      echo ""
      echo "No findings. ✅"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

echo ""
if [ "$TOTAL_BLOCKING" -gt 0 ]; then
  echo "❌ Quality gate failed: $TOTAL_BLOCKING finding(s) at severity '$FAIL_ON' or above."
  exit 1
fi
echo "✅ Quality gate passed (threshold: $FAIL_ON)."
