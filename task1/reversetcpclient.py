"""
TCP Reverse Client — 2026春计网课程实习 Task1
功能：将文本文件按不定长段发送给服务端反转，接收反转结果并输出到新文件。

命令行参数：
  python reversetcpclient.py <server_ip> <server_port> <Lmin> <Lmax> <chunk_seed> <input_file> <StudentID>

自定义报文格式（与服务端一致，Header 9 bytes）:
  - Type:      1 byte  (0x01=Initialization, 0x02=agree, 0x03=reverseRequest, 0x04=reverseAnswer)
  - Sequence:  4 bytes (unsigned int, network byte order)
  - Length:    4 bytes (unsigned int, network byte order)

Initialization 载荷: StudentID(2B) + chunk_seed(4B) + total_chunks(4B) + filename(变长)
"""

import socket
import struct
import random
import sys
import datetime
import os
import time

# ── 报文类型常量（文档规定4种）──
TYPE_INITIALIZATION = 0x01
TYPE_AGREE          = 0x02
TYPE_REVERSE_REQ    = 0x03
TYPE_REVERSE_ANS    = 0x04

HEADER_FORMAT = "!B I I"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

# Initialization 载荷前缀
INIT_PREFIX_FORMAT = "!H I I"  # StudentID(2B) + chunk_seed(4B) + total_chunks(4B)
INIT_PREFIX_SIZE   = struct.calcsize(INIT_PREFIX_FORMAT)


class Logger:
    """运行日志记录器，同时输出到控制台和 run_log.txt"""
    def __init__(self, log_path: str):
        self.f = open(log_path, "w", encoding="utf-8")

    def log(self, msg: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{now}] {msg}"
        print(line, flush=True)
        self.f.write(line + "\n")
        self.f.flush()

    def close(self):
        self.f.close()


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """精确接收 n 字节"""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("连接已关闭")
        data += chunk
    return data


def build_packet(msg_type: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, msg_type, seq, len(payload))
    return header + payload


def parse_header(data: bytes):
    return struct.unpack(HEADER_FORMAT, data)


def main():
    if len(sys.argv) != 8:
        print("用法: python reversetcpclient.py <server_ip> <server_port> <Lmin> <Lmax> <chunk_seed> <input_file> <StudentID>")
        sys.exit(1)

    server_ip    = sys.argv[1]
    server_port  = int(sys.argv[2])
    Lmin         = int(sys.argv[3])
    Lmax         = int(sys.argv[4])
    chunk_seed   = int(sys.argv[5])
    input_file   = sys.argv[6]
    student_id   = int(sys.argv[7])

    if Lmin < 1 or Lmax < Lmin:
        print("错误: 需满足 1 <= Lmin <= Lmax")
        sys.exit(1)

    if student_id <= 0 or student_id > 65535:
        print("错误: StudentID 必须为 1~65535 之间的整数")
        sys.exit(1)

    # ── 准备日志 ──
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_log.txt")
    logger = Logger(log_path)
    logger.log(f"=== TCP Reverse Client 启动 ===")
    logger.log(f"参数: server={server_ip}:{server_port}, Lmin={Lmin}, Lmax={Lmax}, "
               f"chunk_seed={chunk_seed}, file={input_file}, StudentID={student_id}")

    # ── 读取输入文件 ──
    if not os.path.isfile(input_file):
        logger.log(f"错误: 文件不存在 - {input_file}")
        logger.close()
        sys.exit(1)

    with open(input_file, "r", encoding="ascii") as f:
        content = f.read()

    total_len = len(content)
    filename  = os.path.basename(input_file)
    output_file = os.path.splitext(filename)[0] + "_reversed.txt"
    logger.log(f"文件读取完成: {filename}, 总长度={total_len} 字节")

    # ── 使用 chunk_seed 随机确定各块长度（保证验收时可复现）──
    random.seed(chunk_seed)
    segments = []
    pos = 0
    while pos < total_len:
        seg_len = random.randint(Lmin, Lmax)
        seg_len = min(seg_len, total_len - pos)
        segments.append(content[pos:pos + seg_len])
        pos += seg_len
    total_chunks = len(segments)
    logger.log(f"分段完成: 共 {total_chunks} 段 (chunk_seed={chunk_seed})")
    for i, seg in enumerate(segments):
        logger.log(f"  第{i+1}块: {len(seg)} 字节")

    # ── 连接服务器 ──
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    start_time = time.time()
    try:
        sock.connect((server_ip, server_port))
        logger.log(f"已连接到服务器 {server_ip}:{server_port}")
    except ConnectionRefusedError:
        logger.log(f"错误: 无法连接到服务器 {server_ip}:{server_port}")
        logger.close()
        sys.exit(1)

    sent_count = 0
    reversed_result = []

    try:
        # ── 1. 发送 Initialization ──
        init_prefix = struct.pack(INIT_PREFIX_FORMAT, student_id, chunk_seed, total_chunks)
        init_payload = init_prefix + filename.encode("utf-8")
        logger.log(f">>> 发送 Initialization: StudentID={student_id}, chunk_seed={chunk_seed}, "
                   f"total_chunks={total_chunks}, filename={filename}")
        sock.sendall(build_packet(TYPE_INITIALIZATION, 0, init_payload))

        # ── 2. 等待 agree ──
        header_bytes = recv_exact(sock, HEADER_SIZE)
        msg_type, seq, payload_len = parse_header(header_bytes)
        if payload_len > 0:
            recv_exact(sock, payload_len)
        if msg_type != TYPE_AGREE:
            logger.log(f"错误: 期望 agree, 收到 type={msg_type:#x}")
            sock.close()
            logger.close()
            sys.exit(1)
        logger.log(f"<<< 收到 agree")

        # ── 3. 逐段发送 reverseRequest & 接收 reverseAnswer ──
        for i, seg in enumerate(segments):
            block_num = i + 1
            req_pkt = build_packet(TYPE_REVERSE_REQ, block_num, seg.encode("ascii", errors="replace"))
            sock.sendall(req_pkt)
            logger.log(f">>> 发送 reverseRequest 第{block_num}块, 长度={len(seg)} 字节")

            # 接收响应
            header_bytes = recv_exact(sock, HEADER_SIZE)
            rcv_type, rcv_seq, payload_len = parse_header(header_bytes)

            if rcv_type != TYPE_REVERSE_ANS:
                logger.log(f"错误: 期望 reverseAnswer, 收到 type={rcv_type:#x}")
                break

            ans_payload = recv_exact(sock, payload_len) if payload_len > 0 else b""
            reversed_text = ans_payload.decode("ascii", errors="replace")
            reversed_result.append(reversed_text)
            sent_count += 1

            # 命令行打印: "第x块：反转的文本"
            display_text = reversed_text[:60] + ("..." if len(reversed_text) > 60 else "")
            logger.log(f"<<< 第{block_num}块：{display_text}")

    except (ConnectionError, ConnectionResetError, struct.error, TimeoutError) as e:
        logger.log(f"传输异常: {e}")
    finally:
        sock.close()

    elapsed = time.time() - start_time

    # ── 写入输出文件 ──
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_file)
    with open(output_path, "w", encoding="ascii") as f:
        f.write("".join(reversed_result))
    logger.log(f"反转结果已写入: {output_file}")

    # ── 统计 ──
    logger.log(f"=== 传输统计 ===")
    logger.log(f"总耗时: {elapsed:.3f} 秒")
    logger.log(f"分段数/完成数: {len(segments)}/{sent_count}")
    logger.log(f"原始大小: {total_len} 字节")
    logger.log(f"反转后大小: {sum(len(s) for s in reversed_result)} 字节")
    logger.log(f"=== 完成 ===")

    logger.close()


if __name__ == "__main__":
    main()
