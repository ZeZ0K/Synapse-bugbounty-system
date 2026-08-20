#!/usr/bin/env bash
# Negative/positive tests for the two enforcement gates.
# Run: bash .claude/hooks/test_gates.sh
set -uo pipefail

HOOKS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
mkdir -p "$FIX/runs/t/r1/findings/f1"
RUN="$FIX/runs/t/r1"

pass=0; fail=0
check() { # name expected(deny|allow) json_payload
  local name="$1" expect="$2" payload="$3" hook="$4" out
  out=$(printf '%s' "$payload" | python3 "$HOOKS/$hook" 2>&1)
  local got="allow"
  [[ "$out" == *'"deny"'* ]] && got="deny"
  if [[ "$got" == "$expect" ]]; then
    printf '  PASS  %-46s (%s)\n' "$name" "$got"; ((pass++))
  else
    printf '  FAIL  %-46s expected %s got %s\n' "$name" "$expect" "$got"
    [[ -n "$out" ]] && printf '        %s\n' "$(head -c 300 <<<"$out")"
    ((fail++))
  fi
}

cat > "$RUN/operations.json" <<'EOF'
[{"id":"ml.get.map","area":"ml","method":"GET","path_or_selector":"/x","auth_required":"user",
  "mutates_state":false,"notes":"","module":"ml","outcome":null},
 {"id":"ml.post.sim","area":"ml","method":"POST","path_or_selector":"/y","auth_required":"user",
  "mutates_state":false,"notes":"","module":"ml","outcome":"tested"}]
EOF
STATE_BASE='{"target":"t","run_id":"r1","started":"2026-08-11T00:00:00Z","setup":{"mapper_done":true,"provisioner_done":true,"policy_checked":{"done":true}},"blocked":[]'
echo "$STATE_BASE,\"modules\":{\"ml\":\"in_progress\"}}" > "$RUN/state.json"

echo "== gate_module_complete =="
check "complete with an uncovered operation" deny \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$RUN/state.json\",\"content\":\"$(echo "$STATE_BASE,\"modules\":{\"ml\":\"complete\"}}" | sed 's/"/\\"/g')\"}}" \
  gate_module_complete.py
check "leaving module in_progress" allow \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$RUN/state.json\",\"content\":\"$(echo "$STATE_BASE,\"modules\":{\"ml\":\"in_progress\"}}" | sed 's/"/\\"/g')\"}}" \
  gate_module_complete.py
check "unrelated file write" allow \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$FIX/notes.md\",\"content\":\"hi\"}}" \
  gate_module_complete.py
check "module with zero operations" deny \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$RUN/state.json\",\"content\":\"$(echo "$STATE_BASE,\"modules\":{\"ghost\":\"complete\"}}" | sed 's/"/\\"/g')\"}}" \
  gate_module_complete.py
check "malformed state.json (fail closed)" deny \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$RUN/state.json\",\"content\":\"{not json\"}}" \
  gate_module_complete.py

python3 - "$RUN/operations.json" <<'EOF'
import json,sys
p=sys.argv[1]; o=json.load(open(p))
o[0]["outcome"]="excluded"; o[0]["outcome_reason"]="UI-only"
json.dump(o,open(p,"w"))
EOF
check "complete once every operation covered" allow \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$RUN/state.json\",\"content\":\"$(echo "$STATE_BASE,\"modules\":{\"ml\":\"complete\"}}" | sed 's/"/\\"/g')\"}}" \
  gate_module_complete.py

echo "== gate_triage_pass =="
F="$RUN/findings/f1"
PASS_JSON='{\"finding_id\":\"f1\",\"verdict\":\"PASS\",\"conceded_privilege_check\":{\"performed\":true,\"conclusion\":\"not_conceded\",\"sources_checked\":[\"docs\"]},\"severity\":{\"level\":\"high\",\"cvss_vector\":\"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N\",\"cvss_score\":7.7},\"rationale\":\"x\"}'
REJ_JSON='{\"finding_id\":\"f1\",\"verdict\":\"REJECT\",\"conceded_privilege_check\":{\"performed\":true,\"conclusion\":\"already_conceded\",\"sources_checked\":[\"docs\"]},\"severity\":{\"level\":\"none\",\"cvss_vector\":\"AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N\",\"cvss_score\":0},\"rationale\":\"x\"}'

check "PASS with no verify.json at all" deny \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$F/triage.json\",\"content\":\"$PASS_JSON\"}}" \
  gate_triage_pass.py

echo '{"finding_id":"f1","verdict":"COULD_NOT_REPRODUCE","reproduced_from":"poc_steps","evidence_audit":{"items_checked":0,"items_traced":0,"dropped":[]}}' > "$F/verify.json"
check "PASS over COULD_NOT_REPRODUCE" deny \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$F/triage.json\",\"content\":\"$PASS_JSON\"}}" \
  gate_triage_pass.py
check "REJECT over COULD_NOT_REPRODUCE" allow \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$F/triage.json\",\"content\":\"$REJ_JSON\"}}" \
  gate_triage_pass.py

python3 -c "
import json,sys; p='$F/verify.json'; v=json.load(open(p)); v['verdict']='CONFIRMED'; json.dump(v,open(p,'w'))"
check "PASS over CONFIRMED" allow \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$F/triage.json\",\"content\":\"$PASS_JSON\"}}" \
  gate_triage_pass.py
check "malformed triage.json (fail closed)" deny \
  "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$F/triage.json\",\"content\":\"{not json\"}}" \
  gate_triage_pass.py

echo
echo "  $pass passed, $fail failed"
exit $(( fail > 0 ))
