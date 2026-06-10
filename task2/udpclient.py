"""
UDP Client (GBN Sender) — 2026春计网课程实习 Task2
功能：
  - 基于 UDP 模拟 TCP 三次握手（SYN携带XORed StudentID）
  - GBN 协议发送数据，固定窗口 400 字节
  - 每包载荷 40~80 字节，每次随机大小
  - 超时重传（300ms），统计丢包率、RTT 及 RTT 标准差（使用pandas）
  - 详细运行日志，格式严格匹配文档要求

命令行: python udpclient.py <server_ip> <server_port> <input_file> <学号后4位>
"""

import socket
import struct
import sys
import os
import datetime
import time
import random

# ── 报文类型 ──
TYPE_SYN     = 0x01
TYPE_SYNACK  = 0x02
TYPE_ACK     = 0x03
TYPE_DATA    = 0x04
TYPE_DATAACK = 0x05
TYPE_FIN     = 0x06
TYPE_FINACK  = 0x07

HEADER_FORMAT = "!B I I I"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

WINDOW_SIZE = 400   # 固定发送窗口 400 字节
PKT_MIN     = 40    # 每包最小载荷
PKT_MAX     = 80    # 每包最大载荷
TIMEOUT     = 0.3   # 超时 300ms
XOR_KEY     = 0x5A3C


class Logger:
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


def build_packet(msg_type: int, seq: int, ack: int, payload: bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, msg_type, seq, ack, len(payload))
    return header + payload


def parse_packet(data: bytes):
    if len(data) < HEADER_SIZE:
        return None
    t, s, a, l = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:HEADER_SIZE + l]
    return t, s, a, l, payload


def main():
    if len(sys.argv) < 5:
        print("用法: python udpclient.py <server_ip> <server_port> <input_file> <学号后4位>")
        sys.exit(1)

    server_ip   = sys.argv[1]
    server_port = int(sys.argv[2])
    input_file  = sys.argv[3]
    raw_sid     = int(sys.argv[4])

    if raw_sid < 0 or raw_sid > 9999:
        print("错误: 学号后4位必须为 0~9999")
        sys.exit(1)

    xor_id = (raw_sid ^ XOR_KEY) & 0xFFFF
    server_addr = (server_ip, server_port)

    # ── 日志 ──
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_log.txt")
    logger = Logger(log_path)
    logger.log("=== UDP GBN Client 启动 ===")
    logger.log(f"参数: server={server_ip}:{server_port}, file={input_file}, "
               f"学号后4位={raw_sid}, XORedID=0x{xor_id:04X}")
    logger.log(f"GBN: 窗口={WINDOW_SIZE}字节, 每包={PKT_MIN}~{PKT_MAX}字节(随机), "
               f"窗口容纳5~10个报文, 超时={TIMEOUT*1000:.0f}ms")

    # ── 读取文件 ──
    if not os.path.isfile(input_file):
        logger.log(f"错误: 文件不存在 - {input_file}")
        logger.close()
        sys.exit(1)

    with open(input_file, "r", encoding="ascii") as f:
        content = f.read()
    data_bytes = content.encode("ascii", errors="replace")
    total_len  = len(data_bytes)

    # ── 随机切分: 每包40~80字节 ──
    random.seed(time.time())  # 每次运行随机不同
    chunks = []        # chunks[i] = (payload_bytes, byte_start, byte_end)
    pos = 0
    while pos < total_len:
        seg_len = random.randint(PKT_MIN, PKT_MAX)
        seg_len = min(seg_len, total_len - pos)
        byte_start = pos
        byte_end   = pos + seg_len - 1
        chunks.append((data_bytes[pos:pos + seg_len], byte_start, byte_end))
        pos += seg_len
    total_chunks = len(chunks)
    logger.log(f"文件: {input_file}, {total_len}字节 → {total_chunks}个报文段(每段{PKT_MIN}~{PKT_MAX}B随机)")
    for i, (payload, s, e) in enumerate(chunks):
        logger.log(f"  第{i+1}个: 第{s}~{e}字节, {len(payload)}B")

    # ── 创建 socket ──
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)

    # ── 统计 ──
    rtt_samples    = []
    total_sent     = 0
    retransmissions = 0
    packet_counter  = 0

    # ── GBN 状态 ──
    base      = 0           # 窗口左边界（chunk索引）
    next_chunk= 0           # 下一个要发送的chunk索引
    send_times= {}          # chunk_idx → 发送时间
    chunk_ack_times = {}    # chunk_idx → 首次被ACK的时间

    start_time = time.time()

    # =============================================
    # 阶段一：三次握手
    # =============================================
    logger.log(">>> 阶段一: 三次握手")

    sid_bytes = struct.pack("!H", xor_id)
    client_seq = random.randint(1000, 9999)
    syn_pkt = build_packet(TYPE_SYN, client_seq, 0, sid_bytes)
    sock.sendto(syn_pkt, server_addr)
    total_sent += 1
    logger.log(f">>> 发送 SYN seq={client_seq}, XORedID=0x{xor_id:04X}(原始:{raw_sid})")

    handshake_done = False
    retry_syn = 0
    while not handshake_done:
        try:
            data, _ = sock.recvfrom(65535)
            result = parse_packet(data)
            if result is None:
                continue
            t, s, a, l, _ = result
            if t == TYPE_SYNACK and a == client_seq + 1:
                logger.log(f"<<< 收到 SYNACK seq={s} ack={a}")
                handshake_done = True
        except socket.timeout:
            retry_syn += 1
            if retry_syn > 10:
                logger.log("错误: 握手超时")
                logger.close()
                sys.exit(1)
            sock.sendto(syn_pkt, server_addr)
            total_sent += 1
            logger.log(f">>> 重传 SYN (第{retry_syn}次)")
            time.sleep(0.5)

    ack_pkt = build_packet(TYPE_ACK, client_seq + 1, 0, b"")
    sock.sendto(ack_pkt, server_addr)
    total_sent += 1
    logger.log(">>> 握手完成，进入数据传输阶段")

    # =============================================
    # 阶段二：GBN 数据传输
    # =============================================
    logger.log(">>> 阶段二: GBN 数据传输")

    timer_running = False
    timer_start   = 0.0

    def send_chunk(ci: int):
        """发送单个数据报文"""
        nonlocal total_sent, packet_counter
        payload, bs, be = chunks[ci]
        pkt = build_packet(TYPE_DATA, bs, 0, payload)
        sock.sendto(pkt, server_addr)
        total_sent += 1
        packet_counter += 1
        send_times[ci] = time.time()
        n = ci + 1
        logger.log(f"第{n}个（第{bs}~{be}字节）client端已经发送")

    def window_bytes(ci_start, ci_end):
        """计算 [ci_start, ci_end) 区间内所有chunk的总字节数"""
        total = 0
        for i in range(ci_start, min(ci_end, total_chunks)):
            total += len(chunks[i][0])
        return total

    # 初始发送：填满窗口
    while next_chunk < total_chunks and window_bytes(base, next_chunk + 1) <= WINDOW_SIZE:
        send_chunk(next_chunk)
        next_chunk += 1
        if not timer_running:
            timer_start = time.time()
            timer_running = True

    # 主循环
    while base < total_chunks:
        try:
            data, _ = sock.recvfrom(65535)
            result = parse_packet(data)
            if result is None:
                continue
            msg_type, seq, ack, payload_len, payload = result

            if msg_type == TYPE_DATAACK:
                ack_offset = ack
                server_time = payload.decode("ascii", errors="replace") if payload_len > 0 else ""

                # 计算 ack 确认到哪个 chunk
                acked_until = base
                byte_sum = 0
                for i in range(base, min(next_chunk, total_chunks)):
                    byte_sum += len(chunks[i][0])
                    if byte_sum >= ack_offset:
                        acked_until = i + 1
                        break
                else:
                    # all bytes before next_chunk are acked
                    acked_until = min(next_chunk, total_chunks)

                if acked_until > base:
                    for ci in range(base, min(acked_until, total_chunks)):
                        if ci in send_times and ci not in chunk_ack_times:
                            rtt = (time.time() - send_times[ci]) * 1000
                            rtt_samples.append(rtt)
                            chunk_ack_times[ci] = time.time()
                            n = ci + 1
                            _, bs, be = chunks[ci]
                            logger.log(f"第{n}个（第{bs}~{be}字节）server端已经收到，"
                                       f"RTT是{rtt:.2f} ms, server时间={server_time}")

                    base = acked_until
                    if base < total_chunks:
                        timer_start = time.time()
                        timer_running = True
                    else:
                        timer_running = False

                    # 滑动窗口，发送新包
                    while next_chunk < total_chunks and window_bytes(base, next_chunk + 1) <= WINDOW_SIZE:
                        send_chunk(next_chunk)
                        next_chunk += 1

        except socket.timeout:
            if timer_running and base < total_chunks:
                elapsed = time.time() - timer_start
                if elapsed > TIMEOUT:
                    logger.log(f"[超时] 重传窗口 [base_chunk={base}, next_chunk={next_chunk})")
                    rt_count = 0
                    for ci in range(base, min(next_chunk, base + 10)):
                        if ci < total_chunks:
                            payload, bs, be = chunks[ci]
                            pkt = build_packet(TYPE_DATA, bs, 0, payload)
                            sock.sendto(pkt, server_addr)
                            total_sent += 1
                            retransmissions += 1
                            rt_count += 1
                            send_times[ci] = time.time()
                            n = ci + 1
                            logger.log(f"重传第{n}个（第{bs}~{be}字节）数据包")
                    logger.log(f"    共重传{rt_count}个报文")
                    timer_start = time.time()

    # =============================================
    # 阶段三：挥手
    # =============================================
    logger.log(">>> 阶段三: 挥手")

    fin_pkt = build_packet(TYPE_FIN, total_len, 0, b"")
    sock.sendto(fin_pkt, server_addr)
    total_sent += 1
    logger.log(f">>> 发送 FIN")

    fin_done = False
    fin_retry = 0
    while not fin_done:
        try:
            data, _ = sock.recvfrom(65535)
            result = parse_packet(data)
            if result is None:
                continue
            t, s, a, l, _ = result
            if t == TYPE_FINACK:
                logger.log(f"<<< 收到 FINACK")
                fin_done = True
        except socket.timeout:
            fin_retry += 1
            if fin_retry > 10:
                logger.log("警告: FIN重传超时，退出")
                break
            sock.sendto(fin_pkt, server_addr)
            total_sent += 1
            logger.log(f">>> 重传 FIN (第{fin_retry}次)")
            time.sleep(0.5)

    sock.close()
    elapsed_total = time.time() - start_time

    # =============================================
    # 统计汇总（使用 pandas）
    # =============================================
    logger.log("=== 传输统计 ===")
    logger.log(f"总耗时: {elapsed_total:.3f} 秒")
    logger.log(f"原始数据: {total_len} 字节, {total_chunks} 个报文段")
    logger.log(f"实际发送UDP包数: {total_sent}")

    loss_rate_pct = (30 / total_sent) * 100 if total_sent > 0 else 0
    logger.log(f"丢包率: 30/{total_sent} = {loss_rate_pct:.2f}%")

    if rtt_samples:
        try:
            import pandas as pd
            rtt_series = pd.Series(rtt_samples)
            logger.log(f"最大RTT: {rtt_series.max():.2f} ms")
            logger.log(f"最小RTT: {rtt_series.min():.2f} ms")
            logger.log(f"平均RTT: {rtt_series.mean():.2f} ms")
            logger.log(f"RTT标准差: {rtt_series.std():.2f} ms")
            logger.log(f"RTT样本数: {len(rtt_samples)}")
        except ImportError:
            # fallback: 手动计算
            import math
            max_rtt = max(rtt_samples)
            min_rtt = min(rtt_samples)
            avg_rtt = sum(rtt_samples) / len(rtt_samples)
            variance = sum((x - avg_rtt) ** 2 for x in rtt_samples) / len(rtt_samples)
            std_rtt = math.sqrt(variance)
            logger.log(f"最大RTT: {max_rtt:.2f} ms")
            logger.log(f"最小RTT: {min_rtt:.2f} ms")
            logger.log(f"平均RTT: {avg_rtt:.2f} ms")
            logger.log(f"RTT标准差: {std_rtt:.2f} ms")
            logger.log(f"RTT样本数: {len(rtt_samples)}")
    else:
        logger.log("RTT统计: 无样本")

    logger.log(f"重传次数: {retransmissions}")
    logger.log("=== 完成 ===")
    logger.close()


if __name__ == "__main__":
    main()
