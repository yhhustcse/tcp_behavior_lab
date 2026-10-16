# TCP 流重组与软件行为分析课程设计工具链

本仓库用于完成《基于 TCP 流重组的软件行为分析》课程设计。整体流程是：

1. 从 FTP 明文传输的 `pcap/pcapng` 中自动提取控制流信息；
2. 根据 FTP 数据连接重组出传输文件；
3. 生成 `tcp_info.json`，供后续报告自动读取；
4. 在 IDA 中运行 IDAPython 脚本，扫描漏洞与恶意行为；
5. 生成 `课程设计检查表_dynamic.md` 和 `ida_dynamic_analysis.json`；
6. 根据结构化约束自动生成 payload；
7. 使用 QEMU 用户态模拟执行样本，验证漏洞与恶意行为。

## 关于"TCP 流重组"与"FTP"的关系

工具名和源码文件名都带 `ftp`，容易让人误以为做的是"FTP 协议解析"，这里说明清楚边界：

**核心做的是 TCP 流重组，FTP 只负责"确定该重组哪条流"。**

* **TCP 层（通用、与协议无关）**：按四元组区分会话，取 TCP 序号 `seq`，处理乱序、重传去重、重叠区间合并、
  丢包空洞、以及 32 位序号回绕。这一段逻辑换任何应用层协议都成立。
* **FTP 层（本样例的定位手段）**：抄包时并不知道哪条 TCP 流里传的是目标文件。所以要解析控制通道的
  `USER / PASS / PORT / PASV / 227 / RETR / STOR`，从 `PORT` 或 `227` 响应里解出数据连接的 IP 与端口，
  再按 `RETR`（服务器→客户端）或 `STOR`（客户端→服务器）确定传输方向，据此从全流量里筛出该条数据流。

换句话说：**FTP 解析是"取景框"，TCP 流重组才是"相机"**。如果换一个明文协议
（例如 HTTP 下载、TFTP），需要替换的只是"如何定位目标流"这一层，重组内核不用动。
题目给定的样例是 FTP 明文传输，所以这一层按 FTP 实现。

## 目录结构

```text
.
├── Makefile
├── README.md
├── ftp_reassemble_info.c              # pcap/pcapng TCP 流重组（FTP 定位）+ tcp_info.json 输出
├── ida_dynamic_checklist.py           # IDA 内运行，生成 Markdown 报告和 JSON 约束
├── make_payloads_from_dynamic_json.py # 根据 JSON 结构化约束生成 payload
└── run_case.sh                        # QEMU + nc 自动验证单个 payload
```

## 1. Ubuntu 依赖安装

```bash
sudo apt update
sudo apt install -y build-essential gcc make pkg-config
sudo apt install -y libpcap-dev libssl-dev zlib1g-dev
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y qemu-user qemu-user-static libc6:i386 libgcc-s1:i386 libstdc++6:i386 netcat-openbsd psmisc procps xxd
```

如果出现 `/lib/ld-linux.so.2` 缺失，说明 32 位运行库没有装好，重新安装：

```bash
sudo apt install -y libc6:i386 libgcc-s1:i386 libstdc++6:i386
ls -l /lib/ld-linux.so.2
```

如果 `apt update` 报 DNS 解析失败，先修 DNS：

```bash
IFACE=$(ip route | awk '/default/ {print $5; exit}')
sudo resolvectl dns "$IFACE" 8.8.8.8 1.1.1.1
sudo resolvectl domain "$IFACE" "~."
sudo systemctl restart systemd-resolved
sudo apt update
```

## 2. 编译 TCP 流重组程序

```bash
make
```

等价命令：

```bash
gcc -O2 -Wall -Wextra -std=c11 -o ftp_reassemble_info ftp_reassemble_info.c -lpcap -lcrypto -lz
```

## 3. 从 pcapng 重组文件并生成 tcp_info.json

```bash
./ftp_reassemble_info cstest2026-do.pcapng recovered_sample tcp_info.json
```

输出文件：

```text
recovered_sample    # 重组得到的二进制或文件
tcp_info.json       # 自动提取出的 TCP/FTP 信息与文件哈希
```

`tcp_info.json` 示例字段：

```json
{
  "截包文件名": "cstest2026-do.pcapng",
  "重组输出文件": "recovered_sample",
  "客户端 IP": "192.168.33.189",
  "服务器 IP": "192.168.33.45",
  "用户名": "seed",
  "口令": "dees",
  "传输文件名": "cs-test-2026",
  "数据连接模式": "PORT",
  "数据连接监听 IP": "192.168.33.189",
  "数据连接监听端口": "36797",
  "文件 MD5": "828FD067CC1E792EE1F9E5CBAE60A3B0"
}
```

## 4. IDA 自动分析

把以下文件放到同一个目录，或者让 IDA 打开的输入文件目录能访问它们：

```text
recovered_sample
tcp_info.json
ida_dynamic_checklist.py
```

在 IDA 9.x 的 Python Console 中运行：

```python
exec(open(r"D:\path\to\ida_dynamic_checklist.py", encoding="utf-8").read())
```

生成：

```text
课程设计检查表_dynamic.md
ida_dynamic_analysis.json
```

### 为什么要输出 JSON 约束？

旧版本 payload 生成器曾经从 Markdown 中文触发条件中反向解析字节约束，容易遗漏条件。例如：

- `Mal_func5` 的 `gcd` 条件可能被识别为 `gcd` 函数而没有归并到 `Mal_func5`；
- `Vul_func2` 的函数内部条件 `第 11 个字节 > 0x32` 可能没有被写入 payload；
- `第 19 个字节 <= 第 20 个字节` 这类中文关系被解析失败时，payload 会走到 `Try Again`。

现在脚本直接导出结构化约束，例如：

```json
{
  "type": "byte_relation",
  "pos1": 19,
  "op": "<=",
  "pos2": 20
}
```

payload 生成器只读取 JSON 约束，不再解析中文报告，从而保证生成的 payload 与报告条件一致。

## 5. 生成 payload

把 `ida_dynamic_analysis.json`、`课程设计检查表_dynamic.md`、`make_payloads_from_dynamic_json.py` 放在同一目录，运行：

```bash
python3 make_payloads_from_dynamic_json.py
```

生成：

```text
payload_malware_*.bin
payload_vuln_*.bin
```

脚本会追加第九节到 `课程设计检查表_dynamic.md`，包括 payload 表和 QEMU 验证命令。每个 payload 都会做自检：如果结构化约束没有满足，表格中会显示 `FAIL`。

## 6. QEMU 动态验证

确保当前目录有：

```text
recovered_sample
payload_*.bin
run_case.sh
```

验证某个 payload：

```bash
./run_case.sh payload_vuln_Vul_func2.bin
```

它会自动：

1. 启动 `qemu-i386 -strace -d in_asm -D trace.log ./recovered_sample`；
2. 用 `nc` 连接 `127.0.0.1:12345`；
3. 发送指定 payload；
4. 输出 `sample_stdout.log`、`qemu_syscall.log` 和 `trace.log` 中的关键证据。

### 常见验证现象

Double Free：

```bash
./run_case.sh payload_vuln_Vul_func2.bin
grep -Ei "double|free|corrupt|abort|segv|sig" sample_stdout.log qemu_syscall.log trace.log
```

成功时可能看到：

```text
free(): double free detected in tcache 2
qemu: uncaught target signal 6 (Aborted) - core dumped
SIGABRT
```

UAF：

```bash
./run_case.sh payload_vuln_Vul_func3.bin
grep -Ei "Before free|After free|mprotect|free|segv|sig" sample_stdout.log qemu_syscall.log trace.log
```

整数溢出 / 越界写：

```bash
./run_case.sh payload_vuln_Vul_func45.bin
grep -Ei "count|overflow|out-of-bounds|segv|sig" sample_stdout.log qemu_syscall.log trace.log
```

后门监听：

```bash
./run_case.sh payload_malware_Mal_func3.bin
```

若恶意函数执行 `nc -l -p 54321 > hustlogo.png`，需要另开连接发送内容：

```bash
echo "HUSTLOGO_TEST" | nc -q 1 127.0.0.1 54321 || true
ls -l hustlogo.png
cat hustlogo.png
```

## 7. 最终提交建议

最终报告建议包含：

- `课程设计检查表_dynamic.md` 中的 TCP 流重组结果；
- 漏洞表和恶意代码表；
- IDA 自动扫描命中结果；
- 关键函数伪代码截图；
- QEMU 运行命令截图；
- `qemu_syscall.log` 或 `trace.log` 中的触发证据。

## 8. 局限性

本项目是课程设计辅助工具，不是完整符号执行器。它使用启发式静态分析，能自动识别常见模式：

- `system/remove/chmod/rename/fork/socket` 等恶意行为相关调用；
- `strncpy/strcpy/malloc/free/mprotect` 等漏洞相关调用；
- `Double Free`、`UAF`、`整数溢出/越界写`、`栈溢出/边界检查风险`；
- `main` 中常见的输入字节条件。

遇到复杂控制流、混淆、间接调用、多线程或非 FTP 明文传输时，需要人工复核。
