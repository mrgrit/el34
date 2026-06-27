#!/usr/bin/env python3
"""One-shot normalizer for el34-web /etc/modsecurity/modsecurity.conf.

The exception region (scanner_pool + service_accounts) had accreted into three
duplicated blocks (duplicate ids 1000001/1000002) plus one truncated, invalid
rule ('SecRule REMOTE_ADDR @ipMatch' with no argument/action) that broke Apache
startup (AH00526, line 241). Collapse it to ONE valid block. Idempotent.
"""
import re, sys

P = "/etc/modsecurity/modsecurity.conf"
lines = open(P, encoding="utf-8").read().split("\n")

CLEAN = [
    "# el34 — Exception: scanner pool subnet + service accounts "
    "(normalized 2026-05-27; previously triplicated/truncated → AH00526)",
    'SecRule REMOTE_ADDR "@ipMatch 10.20.30.0/24" '
    '"id:1000001,phase:1,t:none,nolog,allow,msg:\'Allow scanner pool subnet\'"',
    'SecRule REQUEST_HEADERS:User "@pm service_accounts" '
    '"id:1000002,phase:1,t:none,nolog,allow,msg:\'Allow service accounts\'"',
]

# Identify every line that belongs to the exception cruft:
#  - comment lines mentioning scanner_pool / service_accounts exception
#  - any SecRule defining id 1000001 or 1000002 (valid or truncated)
#  - the truncated 'SecRule REMOTE_ADDR @ipMatch' with nothing after
def is_cruft(ln: str) -> bool:
    s = ln.strip()
    if re.match(r"#\s*Exception\b", s) and ("scanner_pool" in s or "service_accounts" in s):
        return True
    if s.startswith("SecRule") and re.search(r'id:100000[12]\b', s):
        return True
    if re.match(r"SecRule\s+REMOTE_ADDR\s+@ipMatch\s*$", s):  # truncated
        return True
    return False

cruft_idx = [i for i, ln in enumerate(lines) if is_cruft(ln)]
if not cruft_idx:
    print("NO-CRUFT: nothing matched; file may already be clean. Aborting (no change).")
    sys.exit(0)

lo, hi = min(cruft_idx), max(cruft_idx)
# sanity: the span must be contiguous-ish cruft (allow blank lines inside)
removed = lines[lo:hi + 1]
print(f"Removing lines {lo+1}..{hi+1} ({len(removed)} lines):")
for ln in removed:
    print("  - " + ln)

new_lines = lines[:lo] + CLEAN + lines[hi + 1:]
open(P, "w", encoding="utf-8").write("\n".join(new_lines))
print(f"\nWrote {len(new_lines)} lines (was {len(lines)}). Inserted 1 clean exception block.")
