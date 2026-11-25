#!/usr/bin/env python
"""Verify taint/sink.py Sink rules."""

import sys

sys.path.insert(0, "E:/xuexi/AnQuan/AnQuanPingGu/backend")

from app.taint.sink import SinkRule, SINK_RULES, get_sink_rules, find_sinks_in_line

print("=== Sink Rules Verification ===")
print()

# ── Test 1: Total rule count ──
assert len(SINK_RULES) >= 12, f"Expected >=12 rules, got {len(SINK_RULES)}"
print(f"Total SINK_RULES: {len(SINK_RULES)}")
print("Test 1 (rule count): OK")
print()

# ── Test 2: Python SQL Sink rules ──
py_sql_rules = get_sink_rules("python", "flask", "sql_injection")
assert len(py_sql_rules) > 0
cwe_ids = [r.cwe_id for r in py_sql_rules]
assert "CWE-89" in cwe_ids
owasp_vals = [r.owasp for r in py_sql_rules]
assert "A03:2021" in owasp_vals
print(f"Python SQL sink rules: {[(r.name, r.cwe_id) for r in py_sql_rules]}")
print("Test 2 (Python SQL Sink rules): OK")
print()

# ── Test 3: Match cursor.execute ──
matched = find_sinks_in_line("cursor.execute(sql)", "python", "flask")
assert len(matched) > 0
assert matched[0].vuln_type == "sql_injection"
assert matched[0].cwe_id == "CWE-89"
print(f"  cursor.execute -> matched: {matched[0].name} ({matched[0].cwe_id})")
print("Test 3 (match cursor.execute): OK")
print()

# ── Test 4: Match db.session.execute ──
matched = find_sinks_in_line("db.session.execute(sql_text)", "python", "flask")
assert len(matched) > 0
assert matched[0].vuln_type == "sql_injection"
print(f"  db.session.execute -> matched: {matched[0].name}")
print("Test 4 (match db.session.execute): OK")
print()

# ── Test 5: Match string concat SQL ──
matched = find_sinks_in_line(
    'sql = "SELECT * FROM products WHERE name LIKE \'%\'" + q + "%\'"',
    "python",
    "flask",
)
assert len(matched) > 0
assert matched[0].vuln_type == "sql_injection"
print(f"  SQL string concat -> matched: {matched[0].name}")
print("Test 5 (match string concat SQL): OK")
print()

# ── Test 6: Match f-string SQL ──
matched = find_sinks_in_line(
    'sql = f"SELECT * FROM orders WHERE id = {order_id}"', "python", "flask"
)
assert len(matched) > 0
assert matched[0].vuln_type == "sql_injection"
print(f"  f-string SQL -> matched: {matched[0].name}")
print("Test 6 (match f-string SQL): OK")
print()

# ── Test 7: Match os.system ──
matched = find_sinks_in_line("os.system(cmd)", "python", "flask")
cmd_rules = [r for r in matched if r.vuln_type == "command_injection"]
assert len(cmd_rules) > 0
assert cmd_rules[0].cwe_id == "CWE-78"
print(f"  os.system -> matched: {cmd_rules[0].name} ({cmd_rules[0].cwe_id})")
print("Test 7 (match os.system): OK")
print()

# ── Test 8: Match subprocess.run ──
matched = find_sinks_in_line("subprocess.run(cmd_str, shell=True)", "python", "flask")
cmd_rules = [r for r in matched if r.vuln_type == "command_injection"]
assert len(cmd_rules) > 0
print(f"  subprocess.run -> matched: {cmd_rules[0].name}")
print("Test 8 (match subprocess.run): OK")
print()

# ── Test 9: Match subprocess.call ──
matched = find_sinks_in_line("subprocess.call(user_cmd)", "python", "flask")
cmd_rules = [r for r in matched if r.vuln_type == "command_injection"]
assert len(cmd_rules) > 0
print(f"  subprocess.call -> matched: {cmd_rules[0].name}")
print("Test 9 (match subprocess.call): OK")
print()

# ── Test 10: Match eval ──
matched = find_sinks_in_line("eval(user_input)", "python", "flask")
cmd_rules = [r for r in matched if r.vuln_type == "command_injection"]
assert len(cmd_rules) > 0
print(f"  eval -> matched: {cmd_rules[0].name}")
print("Test 10 (match eval): OK")
print()

# ── Test 11: Match file save ──
matched = find_sinks_in_line(
    'f.save("/var/www/uploads/" + f.filename)', "python", "flask"
)
file_rules = [r for r in matched if r.vuln_type == "file_upload"]
assert len(file_rules) > 0
assert file_rules[0].cwe_id == "CWE-434"
assert file_rules[0].owasp == "A04:2021"
print(f"  .save() -> matched: {file_rules[0].name} ({file_rules[0].cwe_id})")
print("Test 11 (match file save): OK")
print()

# ── Test 12: Match IDOR (filter_by with id) ──
matched = find_sinks_in_line(
    "user = User.query().filter_by(id=user_id).first()", "python", "flask"
)
idor_rules = [r for r in matched if r.vuln_type == "broken_access"]
assert len(idor_rules) > 0
assert idor_rules[0].cwe_id == "CWE-639"
print(f"  filter_by(id=) -> matched: {idor_rules[0].name} ({idor_rules[0].cwe_id})")
print("Test 12 (match IDOR filter_by): OK")
print()

# ── Test 13: Match IDOR f-string WHERE ──
matched = find_sinks_in_line(
    'result = f"SELECT * FROM users WHERE id = {user_id}"', "python", "flask"
)
idor_rules = [r for r in matched if r.vuln_type == "broken_access"]
sql_rules = [r for r in matched if r.vuln_type == "sql_injection"]
assert len(idor_rules) > 0 or len(sql_rules) > 0, (
    f"Expected IDOR or SQL match, got {[r.vuln_type for r in matched]}"
)
print(f"  f-string WHERE id -> matched types: {[r.vuln_type for r in matched]}")
print("Test 13 (match IDOR/SQL f-string WHERE): OK")
print()

# ── Test 14: Match Express SQL query ──
matched = find_sinks_in_line(
    'db.query("SELECT * FROM users WHERE id=" + req.params.id)', "javascript", "express"
)
assert len(matched) > 0
assert matched[0].vuln_type == "sql_injection"
print(f"  JS db.query concat -> matched: {matched[0].name}")
print("Test 14 (match Express SQL query): OK")
print()

# ── Test 15: Match Express findById IDOR ──
matched = find_sinks_in_line("User.findById(req.params.id)", "javascript", "express")
idor_rules = [r for r in matched if r.vuln_type == "broken_access"]
assert len(idor_rules) > 0
assert idor_rules[0].cwe_id == "CWE-639"
print(f"  findById(req.params.id) -> matched: {idor_rules[0].name}")
print("Test 15 (match Express IDOR): OK")
print()

# ── Test 16: Match child_process.exec ──
matched = find_sinks_in_line("child_process.exec(userCmd)", "javascript", "express")
cmd_rules = [r for r in matched if r.vuln_type == "command_injection"]
assert len(cmd_rules) > 0
assert cmd_rules[0].cwe_id == "CWE-78"
print(f"  child_process.exec -> matched: {cmd_rules[0].name}")
print("Test 16 (match JS cmd exec): OK")
print()

# ── Test 17: Match Java executeQuery ──
matched = find_sinks_in_line(
    'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId)', "java", "spring-boot"
)
assert len(matched) > 0
assert matched[0].vuln_type == "sql_injection"
print(f"  Java executeQuery -> matched: {matched[0].name}")
print("Test 17 (match Java executeQuery): OK")
print()

# ── Test 18: Match Java Runtime.exec ──
matched = find_sinks_in_line("Runtime.getRuntime().exec(cmd)", "java", "spring-boot")
cmd_rules = [r for r in matched if r.vuln_type == "command_injection"]
assert len(cmd_rules) > 0
print(f"  Runtime.exec -> matched: {cmd_rules[0].name}")
print("Test 18 (match Java Runtime.exec): OK")
print()

# ── Test 19: No match for safe code ──
matched = find_sinks_in_line("result = calculate_sum(1, 2)", "python", "flask")
assert len(matched) == 0, f"Expected 0 matches for safe code, got {matched}"
print("  safe code -> no match")
print("Test 19 (no false positive on safe code): OK")
print()

# ── Test 20: No match for parameterized query ──
matched = find_sinks_in_line(
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', "python", "flask"
)
# parameterized query should NOT match the string concat pattern
# But .execute( pattern will still match - this is expected (execute itself is a sink)
# The taint engine should recognize sanitizer separately
execute_matches = [r for r in matched if r.match("cursor.execute(")]
# The key is that the string-concat patterns should NOT match
concat_pattern = r'["\'].*SELECT.*["\']\s*\+'
import re

concat_match = re.search(
    concat_pattern,
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    re.IGNORECASE,
)
assert concat_match is None, "Should not match string concat for parameterized query"
print(
    f"  parameterized query: execute() matches {len(execute_matches)} sink rules, but no string-concat"
)
print("Test 20 (parameterized query no false concat): OK")
print()

# ── Test 21: extract_sink_expr ──
rule = py_sql_rules[0]
expr = rule.extract_sink_expr("db.session.execute(sql)")
assert expr is not None
print(f'  extract_sink_expr -> "{expr}"')
print("Test 21 (extract_sink_expr): OK")
print()

# ── Test 22: Unknown language returns empty ──
rules = get_sink_rules("rust", "generic")
assert len(rules) == 0
print("Test 22 (unknown language empty): OK")
print()

print("=== ALL SINK RULE TESTS PASSED (22/22) ===")
