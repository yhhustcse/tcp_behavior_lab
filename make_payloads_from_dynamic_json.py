#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate payloads from ida_dynamic_analysis.json.

Important:
    This script consumes STRUCTURED constraints exported by ida_dynamic_checklist.py.
    It does not parse Chinese trigger text. This fixes the common issue where the
    report text is correct but generated payloads do not actually satisfy byte
    relations or callee-internal constraints.
"""

import json
import os
import re
import math
from typing import Dict, List, Any, Set

JSON_FILE = "ida_dynamic_analysis.json"
REPORT_MD = "课程设计检查表_dynamic.md"
DEFAULT_LEN = 99


def set_byte(p: bytearray, pos_1based: int, val: int) -> None:
    idx = pos_1based - 1
    if idx < 0:
        return
    if idx >= len(p):
        p.extend(b"A" * (idx + 1 - len(p)))
    p[idx] = val & 0xFF


def get_byte(p: bytearray, pos_1based: int) -> int:
    idx = pos_1based - 1
    if 0 <= idx < len(p):
        return p[idx]
    return 0


def constrained_positions(constraints: List[Dict[str, Any]]) -> Set[int]:
    out: Set[int] = set()
    for c in constraints:
        typ = c.get("type")
        if typ == "byte_const":
            out.add(int(c["pos"]))
        elif typ in {"byte_relation", "gcd", "byte_sum_gt"}:
            out.add(int(c["pos1"]))
            out.add(int(c["pos2"]))
    return out


def choose_magic_start(length: int, magic_len: int, constraints: List[Dict[str, Any]]) -> int:
    """Return 0-based start position that avoids constrained bytes if possible."""
    if magic_len <= 0 or magic_len > length:
        return -1
    used = {x - 1 for x in constrained_positions(constraints)}
    # Prefer a late position so it avoids early branch bytes used by many samples.
    for start in range(length - magic_len, -1, -1):
        if all((start + i) not in used for i in range(magic_len)):
            return start
    return max(0, length - magic_len)


def apply_contains(p: bytearray, magic: str, constraints: List[Dict[str, Any]]) -> None:
    if not magic:
        return
    mb = magic.encode("utf-8", errors="ignore")
    if not mb:
        return
    start = choose_magic_start(len(p), len(mb), constraints)
    if start >= 0:
        p[start:start + len(mb)] = mb


def apply_byte_const(p: bytearray, c: Dict[str, Any]) -> None:
    pos = int(c["pos"])
    op = c.get("op", "==")
    val = int(c.get("value", 0)) & 0xFF
    if op == "==":
        set_byte(p, pos, val)
    elif op == "!=":
        set_byte(p, pos, (val + 1) & 0xFF)
    elif op == ">":
        set_byte(p, pos, min(255, val + 1))
    elif op == ">=":
        set_byte(p, pos, val)
    elif op == "<":
        set_byte(p, pos, max(0, val - 1))
    elif op == "<=":
        set_byte(p, pos, val)


def apply_byte_relation(p: bytearray, c: Dict[str, Any]) -> None:
    p1 = int(c["pos1"])
    p2 = int(c["pos2"])
    op = c.get("op", "==")
    if op in {"<", "<="}:
        set_byte(p, p1, 0x01)
        set_byte(p, p2, 0x02)
    elif op in {">", ">="}:
        set_byte(p, p1, 0x03)
        set_byte(p, p2, 0x02)
    elif op == "==":
        set_byte(p, p1, 0x41)
        set_byte(p, p2, 0x41)
    elif op == "!=":
        set_byte(p, p1, 0x41)
        set_byte(p, p2, 0x42)


def apply_gcd(p: bytearray, c: Dict[str, Any]) -> None:
    p1 = int(c["pos1"])
    p2 = int(c["pos2"])
    val = int(c["value"]) & 0xFF
    if val == 0:
        val = 1
    set_byte(p, p1, val)
    set_byte(p, p2, val)


def apply_byte_sum_gt(p: bytearray, c: Dict[str, Any]) -> None:
    p1 = int(c["pos1"])
    p2 = int(c["pos2"])
    threshold = int(c.get("threshold", 0))
    # Make the condition true without relying on defaults.
    val = max(0x41, min(255, threshold + 1))
    set_byte(p, p1, val)
    set_byte(p, p2, val)


def apply_constraints(p: bytearray, constraints: List[Dict[str, Any]], magic: str) -> None:
    # First apply non-contains constraints, then place magic in a non-overlapping area.
    for c in constraints:
        typ = c.get("type")
        if typ == "byte_const":
            apply_byte_const(p, c)
        elif typ == "byte_relation":
            apply_byte_relation(p, c)
        elif typ == "gcd":
            apply_gcd(p, c)
        elif typ == "byte_sum_gt":
            apply_byte_sum_gt(p, c)
    # Put contains string last but avoid constrained positions.
    contains_values = [c.get("value") for c in constraints if c.get("type") == "contains" and c.get("value")]
    apply_contains(p, contains_values[0] if contains_values else magic, constraints)


def constraints_to_text(constraints: List[Dict[str, Any]]) -> str:
    def one(c: Dict[str, Any]) -> str:
        typ = c.get("type")
        if typ == "contains":
            return "包含字符串 `%s`" % c.get("value", "")
        if typ == "byte_const":
            mp = {"==": "为", "!=": "不为", "<": "小于", "<=": "小于等于", ">": "大于", ">=": "大于等于"}
            return "第 %d 个字节%s 0x%02X" % (c["pos"], mp.get(c["op"], c["op"]), int(c["value"]) & 0xFF)
        if typ == "byte_relation":
            mp = {"==": "等于", "!=": "不等于", "<": "小于", "<=": "小于等于", ">": "大于", ">=": "大于等于"}
            return "第 %d 个字节%s第 %d 个字节" % (c["pos1"], mp.get(c["op"], c["op"]), c["pos2"])
        if typ == "gcd":
            return "第 %d 个字节和第 %d 个字节的最大公约数为 %d" % (c["pos1"], c["pos2"], c["value"])
        if typ == "byte_sum_gt":
            return "第 %d 个字节与第 %d 个字节之和大于 0x%02X" % (c["pos1"], c["pos2"], int(c["threshold"]) & 0xFF)
        return str(c)
    return "；".join(one(c) for c in constraints) if constraints else "无结构化约束"


def sanity_check(p: bytearray, constraints: List[Dict[str, Any]]) -> List[str]:
    errors = []
    for c in constraints:
        typ = c.get("type")
        if typ == "contains":
            val = (c.get("value") or "").encode()
            if val and val not in p:
                errors.append("missing contains %r" % val)
        elif typ == "byte_const":
            v = get_byte(p, int(c["pos"]))
            target = int(c["value"]) & 0xFF
            op = c.get("op", "==")
            ok = {"==": v == target, "!=": v != target, "<": v < target, "<=": v <= target, ">": v > target, ">=": v >= target}.get(op, True)
            if not ok:
                errors.append("byte_const failed: %s got 0x%02X" % (c, v))
        elif typ == "byte_relation":
            a = get_byte(p, int(c["pos1"]))
            b = get_byte(p, int(c["pos2"]))
            op = c.get("op", "==")
            ok = {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}.get(op, True)
            if not ok:
                errors.append("byte_relation failed: %s got 0x%02X/0x%02X" % (c, a, b))
        elif typ == "gcd":
            a = get_byte(p, int(c["pos1"]))
            b = get_byte(p, int(c["pos2"]))
            if math.gcd(a, b) != int(c["value"]):
                errors.append("gcd failed: %s got gcd(0x%02X,0x%02X)=%d" % (c, a, b, math.gcd(a, b)))
        elif typ == "byte_sum_gt":
            a = get_byte(p, int(c["pos1"]))
            b = get_byte(p, int(c["pos2"]))
            if a + b <= int(c["threshold"]):
                errors.append("byte_sum_gt failed: %s got %d" % (c, a + b))
    return errors


def safe_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def make_payload(name: str, constraints: List[Dict[str, Any]], magic: str) -> Dict[str, Any]:
    p = bytearray(b"A" * DEFAULT_LEN)
    apply_constraints(p, constraints, magic)
    errors = sanity_check(p, constraints)
    with open(name, "wb") as f:
        f.write(p)
    return {"file": name, "size": len(p), "errors": errors}


def append_report(entries: List[Dict[str, Any]], magic: str) -> None:
    with open(REPORT_MD, "a", encoding="utf-8") as f:
        f.write("\n\n# 九、自动生成的动态验证 Payload\n\n")
        f.write("所有 payload 都由 `ida_dynamic_analysis.json` 中的结构化约束生成；不再解析中文触发条件。检测字符串：`%s`。\n\n" % magic)
        f.write("| 文件 | 目标函数 | 类型 | 长度 | 结构化约束 | 自检 |\n")
        f.write("|---|---|---|---:|---|---|\n")
        for e in entries:
            ok = "OK" if not e["errors"] else "FAIL: " + " ; ".join(e["errors"])
            f.write("| `%s` | `%s` | %s | %d | %s | %s |\n" % (
                e["file"], e["target"], e["type"], e["size"], constraints_to_text(e["constraints"]).replace("|", "\\|"), ok.replace("|", "\\|")))

        f.write("\n## QEMU 验证环境准备\n\n")
        f.write("```bash\n")
        f.write("sudo dpkg --add-architecture i386\n")
        f.write("sudo apt update\n")
        f.write("sudo apt install -y qemu-user qemu-user-static libc6:i386 libgcc-s1:i386 libstdc++6:i386 netcat-openbsd psmisc procps\n")
        f.write("chmod +x recovered_sample\n")
        f.write("```\n\n")

        f.write("## 通用验证脚本\n\n")
        f.write("```bash\n")
        f.write("./tools/run_case.sh payload_vuln_Vul_func2.bin\n")
        f.write("```\n\n")

        f.write("## 所有 payload 验证命令\n\n")
        f.write("```bash\n")
        for e in entries:
            f.write("./tools/run_case.sh %s\n" % e["file"])
        f.write("```\n\n")

        f.write("## 重点现象检查\n\n")
        f.write("```bash\n")
        f.write("grep -Ei \"double|free|corrupt|abort|segv|sigabrt|sigsegv\" sample_stdout.log qemu_syscall.log trace.log 2>/dev/null\n")
        f.write("grep -Ei \"Before free|After free|mprotect|UAF\" sample_stdout.log qemu_syscall.log trace.log 2>/dev/null\n")
        f.write("grep -Ei \"overflow|out-of-bounds|count|alloc_size\" sample_stdout.log qemu_syscall.log trace.log 2>/dev/null\n")
        f.write("grep -Ei \"setenforce|SELinux|auth.log|system.sh|54321|fork|clone\" sample_stdout.log qemu_syscall.log trace.log 2>/dev/null\n")
        f.write("```\n")


def main() -> None:
    if not os.path.exists(JSON_FILE):
        raise SystemExit("[ERROR] %s not found. Run ida_dynamic_checklist.py in IDA first." % JSON_FILE)
    with open(JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    magic = data.get("magic_string") or ""
    outputs = []
    for section, prefix in [("malware", "payload_malware"), ("vulnerabilities", "payload_vuln")]:
        for item in data.get(section, []):
            fn = item.get("函数名") or item.get("function") or "unknown"
            typ = item.get("功能类型") or item.get("漏洞类型") or ""
            constraints = item.get("constraints") or []
            name = "%s_%s.bin" % (prefix, safe_filename(fn))
            meta = make_payload(name, constraints, magic)
            meta.update({"target": fn, "type": typ, "constraints": constraints})
            outputs.append(meta)

    append_report(outputs, magic)
    print("[+] Payloads generated:")
    for e in outputs:
        print("    %-36s -> %-20s %s" % (e["file"], e["target"], "OK" if not e["errors"] else "FAIL"))
        for err in e["errors"]:
            print("       ", err)
    print("[+] Appended QEMU instructions to", REPORT_MD)


if __name__ == "__main__":
    main()
