#!/usr/bin/env python
"""Verify taint/source.py Source rules."""

import sys

sys.path.insert(0, "E:/xuexi/AnQuan/AnQuanPingGu/backend")

from app.taint.source import (
    SourceRule,
    SOURCE_RULES,
    get_source_rules,
    find_sources_in_line,
)

print("=== Source Rules Verification ===")
print()

# ── Test 1: Total rule count ──
assert len(SOURCE_RULES) >= 15, f"Expected >=15 rules, got {len(SOURCE_RULES)}"
print(f"Total SOURCE_RULES: {len(SOURCE_RULES)}")
print("Test 1 (rule count): OK")
print()

# ── Test 2: Flask SQL injection rules ──
flask_sql_rules = get_source_rules("python", "flask", "sql_injection")
assert len(flask_sql_rules) > 0
# Should include Flask-specific and generic rules
rule_names = [r.name for r in flask_sql_rules]
assert any("Flask" in n for n in rule_names), f"Missing Flask rule in {rule_names}"
assert any("generic" in r.framework for r in flask_sql_rules), (
    "Missing generic fallback"
)
print(f"Flask SQL injection rules: {rule_names}")
print("Test 2 (Flask SQL rules): OK")
print()

# ── Test 3: Match Flask request.args.get ──
matched = find_sources_in_line('q = request.args.get("q", "")', "python", "flask")
assert len(matched) > 0, "Expected match for request.args.get"
print(f"  request.args.get -> matched: {matched[0].name}")
print("Test 3 (match request.args.get): OK")
print()

# ── Test 4: Match Flask request.form.get ──
matched = find_sources_in_line('name = request.form.get("name")', "python", "flask")
assert len(matched) > 0
print(f"  request.form.get -> matched: {matched[0].name}")
print("Test 4 (match request.form.get): OK")
print()

# ── Test 5: Match Flask request.json.get ──
matched = find_sources_in_line('data = request.json.get("data")', "python", "flask")
assert len(matched) > 0
print(f"  request.json.get -> matched: {matched[0].name}")
print("Test 5 (match request.json.get): OK")
print()

# ── Test 6: Match Django request.GET.get ──
matched = find_sources_in_line('q = request.GET.get("q")', "python", "django")
assert len(matched) > 0
print(f"  request.GET.get -> matched: {matched[0].name}")
print("Test 6 (match Django request.GET.get): OK")
print()

# ── Test 7: Match file upload ──
matched = find_sources_in_line('f = request.files.get("file")', "python", "flask")
file_upload_rules = [r for r in matched if r.vuln_type == "file_upload"]
assert len(file_upload_rules) > 0, (
    f"Expected file_upload match, got {[r.vuln_type for r in matched]}"
)
print(f"  request.files.get -> matched: {file_upload_rules[0].name}")
print("Test 7 (match file upload): OK")
print()

# ── Test 8: Match sensitive data ──
matched = find_sources_in_line('password = "supersecret123"', "python", "flask")
sensitive_rules = [r for r in matched if r.vuln_type == "sensitive_data"]
assert len(sensitive_rules) > 0, (
    f"Expected sensitive_data match, got {[r.vuln_type for r in matched]}"
)
print(f"  hardcoded password -> matched: {sensitive_rules[0].name}")
print("Test 8 (match sensitive data): OK")
print()

# ── Test 9: Match DATABASE_URL with credentials ──
matched = find_sources_in_line(
    'DATABASE_URL = "postgresql://user:pass@localhost/db"', "python", "flask"
)
sensitive_rules = [r for r in matched if r.vuln_type == "sensitive_data"]
assert len(sensitive_rules) > 0
print(f"  DATABASE_URL with creds -> matched: {sensitive_rules[0].name}")
print("Test 9 (match DATABASE_URL credentials): OK")
print()

# ── Test 10: Match Express req.query ──
matched = find_sources_in_line("const q = req.query.q", "javascript", "express")
assert len(matched) > 0
print(f"  req.query -> matched: {matched[0].name}")
print("Test 10 (match Express req.query): OK")
print()

# ── Test 11: Match Express req.params (IDOR) ──
matched = find_sources_in_line("const id = req.params.id", "javascript", "express")
idor_rules = [r for r in matched if r.vuln_type == "broken_access"]
assert len(idor_rules) > 0, (
    f"Expected broken_access match, got {[r.vuln_type for r in matched]}"
)
print(f"  req.params.id -> matched: {idor_rules[0].name}")
print("Test 11 (match Express IDOR): OK")
print()

# ── Test 12: Match JS sensitive data ──
matched = find_sources_in_line(
    'const secret = "my_super_secret_key"', "javascript", "express"
)
sensitive_rules = [r for r in matched if r.vuln_type == "sensitive_data"]
assert len(sensitive_rules) > 0
print(f"  JS hardcoded secret -> matched: {sensitive_rules[0].name}")
print("Test 12 (match JS sensitive data): OK")
print()

# ── Test 13: Match Java @PathVariable (IDOR) ──
matched = find_sources_in_line("@PathVariable Long id", "java", "spring-boot")
idor_rules = [r for r in matched if r.vuln_type == "broken_access"]
assert len(idor_rules) > 0
print(f"  @PathVariable -> matched: {idor_rules[0].name}")
print("Test 13 (match Java @PathVariable IDOR): OK")
print()

# ── Test 14: Match Java @RequestParam ──
matched = find_sources_in_line("@RequestParam String name", "java", "spring-boot")
assert len(matched) > 0
print(f"  @RequestParam -> matched: {matched[0].name}")
print("Test 14 (match Java @RequestParam): OK")
print()

# ── Test 15: No match for safe code ──
matched = find_sources_in_line("result = calculate_sum(1, 2)", "python", "flask")
assert len(matched) == 0, f"Expected 0 matches, got {matched}"
print("  safe code -> no match")
print("Test 15 (no false positive on safe code): OK")
print()

# ── Test 16: extract_var ──
rule = flask_sql_rules[0]
var = rule.extract_var('q = request.args.get("q")')
assert var == "q", f'Expected "q", got {var}'
var2 = rule.extract_var("not a match line")
assert var2 is None
print(f'  extract_var -> "{var}"')
print("Test 16 (extract_var): OK")
print()

# ── Test 17: Unknown language returns empty ──
rules = get_source_rules("rust", "generic")
assert len(rules) == 0
print("Test 17 (unknown language empty): OK")
print()

print("=== ALL SOURCE RULE TESTS PASSED (17/17) ===")
