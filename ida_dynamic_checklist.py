# -*- coding: utf-8 -*-
"""
IDA dynamic checklist generator.

Run inside IDA / IDAPython:
    exec(open(r"D:\\path\\ida_dynamic_checklist.py", encoding="utf-8").read())

Outputs beside the input binary / IDB:
    - 课程设计检查表_dynamic.md
    - ida_dynamic_analysis.json

Design goal:
    The report is produced from the current IDA database, not from hard-coded
    sample answers. The payload generator consumes structured constraints from
    ida_dynamic_analysis.json instead of re-parsing Chinese prose.
"""

import os
import re
import json

import idc
import idaapi
import idautils
import ida_funcs
import ida_nalt
import ida_lines

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except Exception:
    HAS_HEXRAYS = False

DEFAULT_TCP_INFO = {
    "班级": "",
    "学号": "",
    "姓名": "",
    "截包文件名": "",
    "客户端 IP": "",
    "服务器 IP": "",
    "用户名": "",
    "口令": "",
    "传输文件名": "",
    "数据连接模式": "",
    "数据连接监听 IP": "",
    "数据连接监听端口": "",
    "文件 MD5": "",
}

MAL_CALLS = {
    "system", "popen", "execve", "execl", "execlp", "execv", "execvp",
    "remove", "unlink", "rename", "chmod", "chown",
    "fopen", "fwrite", "fprintf", "open", "write",
    "fork", "vfork", "exit",
    "socket", "bind", "listen", "accept", "connect", "send", "recv",
}

VULN_CALLS = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    "scanf", "__isoc99_scanf",
    "memcpy", "memmove", "strncpy", "snprintf",
    "malloc", "calloc", "realloc", "free", "mprotect", "aligned_alloc",
}

FRAMEWORK_CALLS = {
    "socket", "bind", "listen", "accept", "recv", "send", "close", "htons",
    "printf", "puts", "perror", "memset", "strncpy", "exit",
    "contains_you_are_the_best", "gcd",
}

ALL_DANGER_CALLS = sorted(MAL_CALLS | VULN_CALLS)
REL_WORDS = {
    "==": "为",
    "!=": "不为",
    "<": "小于",
    "<=": "小于等于",
    ">": "大于",
    ">=": "大于等于",
}

NEGATE_OP = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}


def norm_name(name):
    if not name:
        return ""
    name = str(name).strip()
    name = name.replace("@plt", "").replace(".plt", "").replace("__imp_", "")
    if name.startswith("j_"):
        name = name[2:]
    if name.startswith("_"):
        name = name[1:]
    return name


def fmt_ea(ea):
    if ea is None or ea == idaapi.BADADDR:
        return ""
    return "0x%X" % ea


def get_output_dir():
    p = ida_nalt.get_input_file_path()
    if p:
        d = os.path.dirname(p)
        if os.path.isdir(d):
            return d
    return os.path.expanduser("~/Desktop")


def load_tcp_info(out_dir):
    p = os.path.join(out_dir, "tcp_info.json")
    data = dict(DEFAULT_TCP_INFO)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                j = json.load(f)
            for k in data:
                if k in j:
                    data[k] = str(j[k])
        except Exception as e:
            print("[!] Failed to read tcp_info.json:", e)
    return data


def get_func_name_by_ea(ea):
    name = idc.get_func_name(ea)
    return name if name else "sub_%X" % ea


def get_call_target_text(ea):
    names = []
    op = idc.print_operand(ea, 0)
    if op:
        names.append(op)
    target = idc.get_operand_value(ea, 0)
    if target and target != idaapi.BADADDR:
        n1 = idc.get_name(target)
        n2 = idc.get_func_name(target)
        if n1:
            names.append(n1)
        if n2:
            names.append(n2)
    out = []
    for n in names:
        n = norm_name(n)
        if n and n not in out:
            out.append(n)
    return " / ".join(out)


def target_contains(target_text, name):
    target_text = norm_name(target_text)
    name = norm_name(name)
    return target_text == name or target_text.endswith("." + name) or target_text.endswith("_" + name) or name in target_text


def decompile_func(ea):
    if not HAS_HEXRAYS:
        return ""
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return ""
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return ""
        return "\n".join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())
    except Exception as e:
        return "/* decompile failed: %s */" % e


def get_strings_in_text(text):
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text or "")


def scan_calls():
    rows = []
    func_map = {}
    idaapi.auto_wait()
    for f in idautils.Functions():
        fn = get_func_name_by_ea(f)
        end = idc.get_func_attr(f, idc.FUNCATTR_END)
        if end == idaapi.BADADDR:
            continue
        info = func_map.setdefault(fn, {
            "name": fn,
            "ea": f,
            "addr": fmt_ea(f),
            "calls": [],
            "danger_calls": [],
            "strings": [],
            "pseudo": "",
        })
        for ea in idautils.Heads(f, end):
            if idc.print_insn_mnem(ea).lower() != "call":
                continue
            target_text = get_call_target_text(ea)
            disasm = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
            item = {"ea": ea, "addr": fmt_ea(ea), "target": target_text, "disasm": disasm, "matched": ""}
            info["calls"].append(item)
            for danger in ALL_DANGER_CALLS:
                if target_contains(target_text, danger):
                    item["matched"] = danger
                    info["danger_calls"].append(item)
                    rows.append({
                        "函数": fn,
                        "函数地址": fmt_ea(f),
                        "调用地址": fmt_ea(ea),
                        "危险函数": danger,
                        "目标": target_text,
                        "反汇编": disasm,
                    })
                    break
    return rows, func_map


def fill_pseudocode(func_map):
    for info in func_map.values():
        text = decompile_func(info["ea"])
        info["pseudo"] = text
        info["strings"] = get_strings_in_text(text)


def parse_local_var_offsets(main_text):
    offsets = {}
    dest_base = None
    # Hex-Rays 32-bit x86 usually prints: char n56; // [esp+2h] [ebp-19Ah]
    pat = re.compile(r'\b(?:char|_BYTE|unsigned char|signed char)\s+([A-Za-z_][A-Za-z0-9_]*)\b(?:\[[^\]]+\])?.*//\s*\[esp\+([0-9A-Fa-f]+)h\]')
    for line in main_text.splitlines():
        m = pat.search(line)
        if not m:
            continue
        name = m.group(1)
        off = int(m.group(2), 16)
        offsets[name] = off
        if name == "dest":
            dest_base = off
    var_to_index = {}
    if dest_base is not None:
        for name, off in offsets.items():
            if off >= dest_base:
                var_to_index[name] = off - dest_base + 1
    var_to_index["dest[0]"] = 1
    var_to_index["dest[1]"] = 2
    return var_to_index


def find_magic_string(func_map):
    for fn, info in func_map.items():
        if "contain" in fn.lower() or "best" in fn.lower():
            for s in info.get("strings", []):
                if len(s) >= 4:
                    return s
    for info in func_map.values():
        for s in info.get("strings", []):
            if "best" in s.lower():
                return s
    return ""


def split_bool_expr(expr):
    parts = []
    for p in re.split(r'\s*&&\s*', expr):
        p = p.strip()
        if p:
            parts.append(p)
    return parts


def strip_wrapping_parens(s):
    s = s.strip()
    changed = True
    while changed and s.startswith("(") and s.endswith(")"):
        changed = False
        depth = 0
        ok = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    ok = False
                    break
        if ok:
            s = s[1:-1].strip()
            changed = True
    return s


def var_to_pos(var, var_to_index):
    var = var.strip()
    m = re.fullmatch(r'dest\[(\d+)\]', var)
    if m:
        return int(m.group(1)) + 1
    return var_to_index.get(var)


def parse_condition_to_constraints(cond, var_to_index, magic_string=""):
    result = []
    for raw in split_bool_expr(cond):
        neg = False
        c = strip_wrapping_parens(raw.strip())
        if c.startswith("!"):
            neg = True
            c = strip_wrapping_parens(c[1:].strip())

        if "contains" in c:
            if magic_string:
                result.append({"type": "contains", "value": magic_string})
            continue

        m = re.fullmatch(r'dest\[(\d+)\]\s*(==|!=|<=|>=|<|>)\s*(\d+)', c)
        if m:
            op = NEGATE_OP.get(m.group(2), m.group(2)) if neg else m.group(2)
            result.append({"type": "byte_const", "pos": int(m.group(1)) + 1, "op": op, "value": int(m.group(3)) & 0xFF})
            continue

        m = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=|<=|>=|<|>)\s*(\d+)', c)
        if m and var_to_pos(m.group(1), var_to_index):
            op = NEGATE_OP.get(m.group(2), m.group(2)) if neg else m.group(2)
            result.append({"type": "byte_const", "pos": var_to_pos(m.group(1), var_to_index), "op": op, "value": int(m.group(3)) & 0xFF})
            continue

        m = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=|<=|>=|<|>)\s*([A-Za-z_][A-Za-z0-9_]*)', c)
        if m and var_to_pos(m.group(1), var_to_index) and var_to_pos(m.group(3), var_to_index):
            op = NEGATE_OP.get(m.group(2), m.group(2)) if neg else m.group(2)
            result.append({"type": "byte_relation", "pos1": var_to_pos(m.group(1), var_to_index), "op": op, "pos2": var_to_pos(m.group(3), var_to_index)})
            continue

        m = re.search(r'gcd\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*==\s*(\d+)', c)
        if m and var_to_pos(m.group(1), var_to_index) and var_to_pos(m.group(2), var_to_index):
            # Only exact gcd equality is useful for payload generation.
            if not neg:
                result.append({"type": "gcd", "pos1": var_to_pos(m.group(1), var_to_index), "pos2": var_to_pos(m.group(2), var_to_index), "value": int(m.group(3)) & 0xFF})
            continue

    return result


def negate_condition(cond):
    return "!(%s)" % cond if cond else ""


def extract_condition_from_if(line):
    line = line.strip()
    m = re.match(r'(?:else\s+)?if\s*\(', line)
    if not m:
        return None
    start = line.find("(")
    depth = 0
    for i in range(start, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                return line[start + 1:i].strip()
    return None


def extract_call_name(line):
    line = line.strip()
    m = re.search(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*;', line)
    if not m:
        return None
    name = m.group(1)
    if name in {"if", "while", "for", "switch", "return", "sizeof"}:
        return None
    return name


def extract_triggers_from_main(main_text, var_to_index, magic_string):
    """Return map: target function -> {constraints, raw_conditions}."""
    triggers = {}
    stack = []
    pending = []
    depth = 0
    last_popped_conditions = []

    for raw in main_text.splitlines():
        line = raw.strip()
        if not line:
            continue

        # Pop leading braces. Hex-Rays often emits a line containing only '}'.
        while line.startswith("}"):
            if stack:
                popped = stack.pop()
                last_popped_conditions = popped.get("conditions", [])
            depth = max(0, depth - 1)
            line = line[1:].strip()

        if not line:
            continue

        if line.startswith("else if"):
            c = extract_condition_from_if(line)
            pending = []
            for pc in last_popped_conditions:
                pending.append(negate_condition(pc))
            if c:
                pending.append(c)
        elif line.startswith("else"):
            pending = [negate_condition(pc) for pc in last_popped_conditions]
        else:
            c = extract_condition_from_if(line)
            if c:
                pending = [c]

        call_name = extract_call_name(line)
        if call_name:
            raw_conditions = []
            constraints = []
            for frame in stack:
                for c in frame.get("conditions", []):
                    raw_conditions.append(c)
                    constraints.extend(parse_condition_to_constraints(c, var_to_index, magic_string))
            for c in pending:
                raw_conditions.append(c)
                constraints.extend(parse_condition_to_constraints(c, var_to_index, magic_string))
            triggers.setdefault(call_name, {"raw_conditions": [], "constraints": []})
            triggers[call_name]["raw_conditions"].append(raw_conditions)
            triggers[call_name]["constraints"].extend(constraints)

        opens = line.count("{")
        closes = line.count("}")
        for _ in range(opens):
            depth += 1
            if pending:
                stack.append({"depth": depth, "conditions": pending})
                pending = []
            else:
                stack.append({"depth": depth, "conditions": []})
        for _ in range(closes):
            if stack:
                popped = stack.pop()
                last_popped_conditions = popped.get("conditions", [])
            depth = max(0, depth - 1)

    # Deduplicate constraints for each target.
    for v in triggers.values():
        seen = set()
        uniq = []
        for c in v["constraints"]:
            key = json.dumps(c, sort_keys=True, ensure_ascii=False)
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        v["constraints"] = uniq
    return triggers


def calls_in_func(info):
    return [c["matched"] for c in info.get("danger_calls", []) if c.get("matched")]


def call_addrs(info, names):
    out = []
    for c in info.get("danger_calls", []):
        if c.get("matched") in names:
            out.append("%s: %s" % (c["matched"], c["addr"]))
    return "；".join(out)


def classify_malware(info):
    text = info.get("pseudo", "")
    strings = info.get("strings", [])
    calls = set(calls_in_func(info))
    joined = " ".join(strings) + " " + text
    if "setenforce 0" in joined or "SELinux" in joined:
        return "禁用系统保护功能"
    if "nc -l" in joined or "/bin/bash" in joined or "/bin/sh" in joined or "bash -i" in joined:
        return "开启后门"
    if "fork" in calls:
        return "创建僵尸进程"
    if {"remove", "unlink", "rename", "chmod", "chown", "fopen", "fwrite", "open", "write"} & calls:
        return "系统文件删除或修改"
    if {"socket", "bind", "listen", "accept", "connect"} & calls:
        return "网络通信/监听行为"
    if "system" in calls:
        return "执行系统命令"
    return ""


def classify_vuln(info):
    text = info.get("pseudo", "")
    calls = set(calls_in_func(info))
    free_count = sum(1 for c in info.get("danger_calls", []) if c.get("matched") == "free")
    if free_count >= 2:
        return "重复释放 Double Free"
    m = re.search(r'free\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', text)
    if m:
        var = m.group(1)
        after = text[text.find(m.group(0)) + len(m.group(0)):]
        if re.search(r'\b%s\b' % re.escape(var), after):
            return "释放后重用 UAF"
    if "overflow" in text.lower() or "out-of-bounds" in text.lower() or re.search(r'\*\([^\n]+-[^\n]+\)\s*=', text):
        return "整数溢出 / 越界写"
    if "gets" in calls or "strcpy" in calls or "sprintf" in calls or "vsprintf" in calls:
        if "malloc" in calls or "aligned_alloc" in calls:
            return "堆溢出"
        return "栈溢出"
    if "memcpy" in calls or "memmove" in calls or "strncpy" in calls:
        return "栈溢出 / 边界检查风险"
    if {"malloc", "free", "mprotect", "aligned_alloc"} & calls:
        return "堆相关漏洞"
    return ""


def describe_malware(info):
    calls = set(calls_in_func(info))
    text = info.get("pseudo", "")
    strings = list(dict.fromkeys(info.get("strings", [])))
    if "remove" in calls or "unlink" in calls:
        targets = [s for s in strings if "/" in s]
        return "调用删除类函数删除文件：%s。" % ("，".join("`%r`" % t for t in targets) if targets else "目标文件")
    if "rename" in calls or "chmod" in calls:
        snippets = []
        for pat in [r'rename\([^\n;]+\)', r'chmod\([^\n;]+\)', r'system\([^\n;]+\)']:
            snippets.extend(re.findall(pat, text))
        return "调用文件修改/权限修改相关函数：%s。" % "；".join("`%s`" % s for s in snippets[:4])
    if "system" in calls or "popen" in calls:
        cmds = []
        for s in strings:
            if any(x in s for x in ["nc", "setenforce", ".sh", "bash", "sh "]):
                if s not in cmds:
                    cmds.append(s)
        return "调用系统命令执行函数：%s。" % ("；".join("`%s`" % c for c in cmds) if cmds else "需人工确认命令参数")
    if "fork" in calls:
        return "调用 fork/vfork 创建子进程，若结合循环或 exit，可能造成大量子进程或僵尸进程。"
    if {"socket", "bind", "listen", "accept"} & calls:
        return "调用 socket/bind/listen/accept 建立监听服务，可能用于网络通信或后门。"
    return "存在可疑恶意行为相关调用，需结合伪代码人工确认。"


def malware_harm(mtype):
    return {
        "系统文件删除或修改": "可能破坏系统文件、日志或权限，隐藏攻击痕迹或影响系统完整性。",
        "开启后门": "可能开放额外端口或 shell，导致远程数据传输或命令执行。",
        "创建僵尸进程": "可能消耗系统进程资源，造成拒绝服务。",
        "禁用系统保护功能": "降低系统强制访问控制或安全防护能力。",
        "网络通信/监听行为": "可能建立隐蔽通信通道或监听端口。",
    }.get(mtype, "可能造成未授权操作或安全风险。")


def describe_vuln(info, vtype):
    text = info.get("pseudo", "")
    if vtype == "重复释放 Double Free":
        m = re.search(r'free\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', text)
        ptr = m.group(1) if m else "同一指针"
        return "函数中对同一堆指针 `%s` 存在多次 free 调用，第一次释放后再次释放同一内存块，形成 Double Free。" % ptr
    if vtype == "释放后重用 UAF":
        m = re.search(r'free\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', text)
        ptr = m.group(1) if m else "ptr"
        return "函数中调用 `free(%s)` 后仍继续访问该指针，形成释放后重用。" % ptr
    if vtype == "整数溢出 / 越界写":
        return "函数中存在整数运算溢出或越界写特征，可能导致分配大小错误或非法内存写入。"
    m = re.search(r'char\s+([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]', text)
    if vtype.startswith("栈溢出") and m:
        return "函数中存在栈缓冲区 `%s[%s]`，并调用 `strncpy` 等拷贝/写入函数；若源数据长度或计算得到的拷贝长度超过目标缓冲区大小，则会造成栈溢出或边界错误。" % (m.group(1), m.group(2))
    if vtype == "堆溢出":
        return "函数中存在堆分配后向堆缓冲区拷贝数据的操作，若源数据长度超过堆块大小会造成堆溢出。"
    return "函数中存在堆内存或危险函数调用，需要结合伪代码确认漏洞成因。"


def vuln_effect(vtype):
    if "Double Free" in vtype:
        return "可能破坏堆管理结构，导致程序崩溃，严重时可被利用执行任意代码。"
    if "UAF" in vtype:
        return "可能导致程序崩溃、数据破坏或被利用执行任意代码。"
    if "溢出" in vtype or "越界" in vtype:
        return "可能造成程序崩溃、内存破坏或控制流劫持。"
    return "可能造成内存破坏或程序异常。"


def add_internal_constraints(info, constraints):
    """Derive intra-procedural input constraints from callee pseudocode.

    Examples handled generically:
      if (*(char *)(p_dest + 10) > 50) free(ptr)
      strncpy(dest, ..., *(char *)(p_dest + 50) + *(char *)(p_dest + 70)) where dest[24]
    """
    text = info.get("pseudo", "")
    out = list(constraints or [])

    # Byte dereference comparisons: *(char *)(p_dest + 10) > 50
    for m in re.finditer(r'\*\(char \*\)\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*(\d+)\s*\)\s*(==|!=|<=|>=|<|>)\s*(\d+)', text):
        out.append({"type": "byte_const", "pos": int(m.group(1)) + 1, "op": m.group(2), "value": int(m.group(3)) & 0xFF, "source": "callee"})

    # strncpy stack overflow length from two input bytes.
    dest = re.search(r'char\s+[A-Za-z_][A-Za-z0-9_]*\[(\d+)\]', text)
    if dest and "strncpy" in text:
        # Search for two p_dest dereferences in the same strncpy expression.
        for call in re.findall(r'strncpy\([^;]+\)', text, flags=re.S):
            offs = re.findall(r'\*\(char \*\)\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*(\d+)\s*\)', call)
            if len(offs) >= 2:
                out.append({"type": "byte_sum_gt", "pos1": int(offs[-2]) + 1, "pos2": int(offs[-1]) + 1, "threshold": int(dest.group(1)), "source": "callee"})
                break

    # Deduplicate.
    seen = set()
    uniq = []
    for c in out:
        key = json.dumps(c, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq


def constraint_to_text(c):
    typ = c.get("type")
    if typ == "contains":
        return "输入需要包含字符串 `%s`" % c.get("value", "")
    if typ == "byte_const":
        return "输入第 %d 个字节%s 0x%02X" % (c["pos"], REL_WORDS.get(c["op"], c["op"]), c["value"] & 0xFF)
    if typ == "byte_relation":
        return "输入第 %d 个字节%s第 %d 个字节" % (c["pos1"], REL_WORDS.get(c["op"], c["op"]), c["pos2"])
    if typ == "gcd":
        return "输入第 %d 个字节和第 %d 个字节的最大公约数为 %d；可取二者均为 0x%02X" % (c["pos1"], c["pos2"], c["value"], c["value"] & 0xFF)
    if typ == "byte_sum_gt":
        return "输入第 %d 个字节与第 %d 个字节之和大于 0x%02X" % (c["pos1"], c["pos2"], c["threshold"] & 0xFF)
    return "需人工确认"


def constraints_to_text(constraints, include_contains=False):
    texts = []
    for c in constraints:
        if c.get("type") == "contains" and not include_contains:
            continue
        t = constraint_to_text(c)
        if t and t not in texts:
            texts.append(t)
    if not texts:
        return "未在 main 中自动提取到触发条件，需人工确认。"
    return "；".join(texts) + "。"


def build_entries(func_map, triggers, magic_string):
    vuln_entries = []
    mal_entries = []
    for fn, info in sorted(func_map.items(), key=lambda kv: kv[1]["ea"]):
        if fn == "main" or fn.startswith(".") or fn.startswith("_"):
            continue
        calls = set(calls_in_func(info))
        if not calls:
            continue

        base = triggers.get(fn, {"constraints": []}).get("constraints", [])
        # Ensure contains string is represented structurally if a magic string exists and target is reached from main.
        if magic_string and any(c.get("type") == "contains" for c in base) is False and fn in triggers:
            base = [{"type": "contains", "value": magic_string}] + base

        vtype = classify_vuln(info)
        if vtype:
            danger = [c for c in calls if c in VULN_CALLS]
            constraints = add_internal_constraints(info, base)
            vuln_entries.append({
                "编号": "漏洞 %d" % (len(vuln_entries) + 1),
                "漏洞类型": vtype,
                "函数名": fn,
                "函数地址": fmt_ea(info["ea"]),
                "导致漏洞的函数": ", ".join(sorted(danger)) if danger else "需人工确认",
                "函数被调用地址": call_addrs(info, set(danger)) or "需人工确认",
                "漏洞成因": describe_vuln(info, vtype),
                "触发条件": constraints_to_text(constraints),
                "影响": vuln_effect(vtype),
                "constraints": constraints,
            })

        mtype = classify_malware(info)
        if mtype:
            # Filter framework-like non-malicious functions by excluding main above; all other network funcs remain candidates.
            danger = [c for c in calls if c in MAL_CALLS]
            constraints = add_internal_constraints(info, base)
            mal_entries.append({
                "编号": "恶意代码 %d" % (len(mal_entries) + 1),
                "功能类型": mtype,
                "函数名": fn,
                "函数地址": fmt_ea(info["ea"]),
                "使用的系统调用": ", ".join(sorted(danger)) if danger else "需人工确认",
                "函数被调用地址": call_addrs(info, set(danger)) or "需人工确认",
                "具体功能描述": describe_malware(info),
                "触发条件": constraints_to_text(constraints),
                "危害": malware_harm(mtype),
                "constraints": constraints,
            })
    return vuln_entries, mal_entries


def md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", "<br>")


def write_md(path, tcp_info, vuln_entries, mal_entries, danger_rows, func_map, triggers, magic_string):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# 《基于 TCP 流重组的软件行为分析》课程设计检查表动态报告\n\n")
        f.write("> 本报告由 IDA 当前数据库自动生成。TCP 信息读取自 `tcp_info.json`；漏洞/恶意行为表来自当前样本危险调用、字符串与 Hex-Rays 伪代码；payload 使用结构化约束生成，不再反向解析中文触发条件。\n\n")

        f.write("## 一、基本信息\n\n| 字段 | 内容 |\n|---|---|\n")
        for k in ["班级", "学号", "姓名", "截包文件名"]:
            f.write("| %s | %s |\n" % (k, md_escape(tcp_info.get(k, ""))))

        f.write("\n## 二、TCP 流重组结果（40 分）\n\n| 检查项 | 结果 |\n|---|---|\n")
        for k in ["客户端 IP", "服务器 IP", "用户名", "口令", "传输文件名", "数据连接模式", "数据连接监听 IP", "数据连接监听端口", "文件 MD5"]:
            f.write("| %s | `%s` |\n" % (k, md_escape(tcp_info.get(k, ""))))

        f.write("\n## 三、软件行为分析：漏洞结果\n\n")
        f.write("| 编号 | 漏洞类型 | 漏洞函数 | 函数地址 | 导致漏洞的函数 | 函数被调用地址 | 漏洞成因 | 触发条件 | 影响 |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for e in vuln_entries:
            f.write("| {编号} | {漏洞类型} | `{函数名}` | `{函数地址}` | `{导致漏洞的函数}` | `{函数被调用地址}` | {漏洞成因} | {触发条件} | {影响} |\n".format(**{k: md_escape(v) for k, v in e.items() if k != "constraints"}))

        f.write("\n## 四、软件行为分析：恶意代码结果\n\n")
        f.write("| 编号 | 功能类型 | 函数名 | 函数地址 | 使用的系统调用 | 函数被调用地址 | 具体功能描述 | 触发条件 | 危害 |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for e in mal_entries:
            f.write("| {编号} | {功能类型} | `{函数名}` | `{函数地址}` | `{使用的系统调用}` | `{函数被调用地址}` | {具体功能描述} | {触发条件} | {危害} |\n".format(**{k: md_escape(v) for k, v in e.items() if k != "constraints"}))

        f.write("\n## 五、IDA 自动扫描命中结果\n\n")
        f.write("| 序号 | 函数 | 函数地址 | 调用地址 | 危险函数 | 目标 | 反汇编 |\n|---:|---|---|---|---|---|---|\n")
        for i, r in enumerate(danger_rows, 1):
            f.write("| %d | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` |\n" % (
                i, md_escape(r["函数"]), md_escape(r["函数地址"]), md_escape(r["调用地址"]), md_escape(r["危险函数"]), md_escape(r["目标"]), md_escape(r["反汇编"])))

        f.write("\n## 六、目标函数触发条件自动提取结果\n\n")
        f.write("检测字符串：`%s`\n\n" % md_escape(magic_string))
        f.write("| 目标函数 | 自动提取条件 |\n|---|---|\n")
        for e in mal_entries + vuln_entries:
            f.write("| `%s` | %s |\n" % (md_escape(e["函数名"]), md_escape(e["触发条件"])))

        f.write("\n## 七、关键函数伪代码备查\n\n")
        key_names = [e["函数名"] for e in mal_entries + vuln_entries]
        if "main" in func_map:
            key_names.append("main")
        seen = set()
        for fn in key_names:
            if fn in seen or fn not in func_map:
                continue
            seen.add(fn)
            f.write("### %s `%s`\n\n" % (fn, fmt_ea(func_map[fn]["ea"])))
            f.write("```c\n%s\n```\n\n" % func_map[fn].get("pseudo", ""))

        f.write("\n## 八、动态验证建议\n\n")
        f.write("先运行 `tools/make_payloads_from_dynamic_json.py` 生成 payload，再使用 `tools/run_case.sh` 或下方命令验证。课程指导手册要求使用 QEMU 用户态执行样本，并通过 `-strace -d in_asm -D trace.log` 记录系统调用和指令日志。\n\n")
        f.write("```bash\nchmod +x recovered_sample\nqemu-i386 -strace -d in_asm -D trace.log ./recovered_sample\ncat payload_*.bin | nc 127.0.0.1 12345\n```\n")


def main():
    idaapi.auto_wait()
    out_dir = get_output_dir()
    tcp_info = load_tcp_info(out_dir)
    danger_rows, func_map = scan_calls()
    fill_pseudocode(func_map)

    main_text = func_map.get("main", {}).get("pseudo", "")
    var_to_index = parse_local_var_offsets(main_text)
    magic_string = find_magic_string(func_map)
    triggers = extract_triggers_from_main(main_text, var_to_index, magic_string)
    vuln_entries, mal_entries = build_entries(func_map, triggers, magic_string)

    md_path = os.path.join(out_dir, "课程设计检查表_dynamic.md")
    json_path = os.path.join(out_dir, "ida_dynamic_analysis.json")

    write_md(md_path, tcp_info, vuln_entries, mal_entries, danger_rows, func_map, triggers, magic_string)

    data = {
        "tcp_info": tcp_info,
        "magic_string": magic_string,
        "var_to_index": var_to_index,
        "vulnerabilities": vuln_entries,
        "malware": mal_entries,
        "danger_rows": danger_rows,
        "generated_by": "ida_dynamic_checklist.py",
        "notes": "Payload generator must use structured constraints, not Chinese trigger text.",
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print("[+] Markdown written:", md_path)
    print("[+] JSON written:", json_path)
    print("[+] magic string:", magic_string)
    print("[+] vulnerabilities:", len(vuln_entries), "malware:", len(mal_entries))


if __name__ == "__main__":
    main()
