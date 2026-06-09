"""
TCP Reverse Server — 2026春计网课程实习 Task1
功能：接收客户端发送的文本段，反转后返回，支持多客户端并发。

自定义报文格式（Header 9 bytes）:
  - Type:      1 byte  (0x01=Initialization, 0x02=agree, 0x03=reverseRequest, 0x04=reverseAnswer)
  - Sequence:  4 bytes (unsigned int, network byte order)
  - Length:    4 bytes (unsigned int, network byte order)
  Payload: 变长

Initialization 报文 Payload 结构:
  - StudentID:   2 bytes (unsigned short, network byte order)
  - chunk_seed:  4 bytes (unsigned int, network byte order)
  - total_chunks: 4 bytes (unsigned int, network byte order)
  - filename:    变长 (UTF-8)
"""

import socket
import struct
import threading
import sys
import datetime

# ── 报文类型常量（文档规定4种）──
TYPE_INITIALIZATION = 0x01
TYPE_AGREE          = 0x02
TYPE_REVERSE_REQ    = 0x03
TYPE_REVERSE_ANS    = 0x04

HEADER_FORMAT = "!B I I"   # Type(1B) + Seq(4B) + Len(4B)
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # 9 bytes

# Initialization 载荷前缀大小
INIT_PREFIX_FORMAT = "!H I I"  # StudentID(2B) + chunk_seed(4B) + total_chunks(4B)
INIT_PREFIX_SIZE   = struct.calcsize(INIT_PREFIX_FORMAT)  # 10 bytes


def log(msg: str):
    """带时间戳的日志输出"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{now}] {msg}", flush=True)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """精确接收 n 字节数据"""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("连接已关闭")
        data += chunk
    return data


def build_packet(msg_type: int, seq: int, payload: bytes) -> bytes:
    """构造自定义报文"""
    header = struct.pack(HEADER_FORMAT, msg_type, seq, len(payload))
    return header + payload


def parse_header(data: bytes) -> tuple:
    """解析9字节头部，返回 (type, seq, length)"""
    return struct.unpack(HEADER_FORMAT, data)


def handle_client(conn: socket.socket, addr: tuple, client_id: int):
    """处理单个客户端连接"""
    log(f"[Client-{client_id}] 来自 {addr} 的连接已建立")

    filename = ""
    total_chunks = 0
    chunk_count = 0
    reversed_parts = []

    try:
        # ── 等待 Initialization ──
        header_bytes = recv_exact(conn, HEADER_SIZE)
        msg_type, seq, payload_len = parse_header(header_bytes)
        payload = recv_exact(conn, payload_len) if payload_len > 0 else b""

        if msg_type != TYPE_INITIALIZATION:
            log(f"[Client-{client_id}] 错误: 首报文不是Initialization, type={msg_type:#x}")
            conn.close()
            return

        # 解析 Initialization 载荷
        if payload_len < INIT_PREFIX_SIZE:
            log(f"[Client-{client_id}] 错误: Initialization载荷过短 ({payload_len}B < {INIT_PREFIX_SIZE}B)")
            conn.close()
            return

        student_id, chunk_seed, total_chunks = struct.unpack(INIT_PREFIX_FORMAT, payload[:INIT_PREFIX_SIZE])
        filename = payload[INIT_PREFIX_SIZE:].decode("utf-8")

        # ── 校验 StudentID（非0视为合法）──
        if student_id == 0:
            log(f"[Client-{client_id}] 错误: 非法的StudentID={student_id}, 拒绝连接")
            conn.close()
            return

        log(f"[Client-{client_id}] Initialization: StudentID={student_id}, chunk_seed={chunk_seed}, "
            f"total_chunks={total_chunks}, filename={filename}")

        # ── 发送 agree ──
        agree_pkt = build_packet(TYPE_AGREE, 0, b"")
        conn.sendall(agree_pkt)
        log(f"[Client-{client_id}] >>> 发送 agree")

        # ── 逐块处理 reverseRequest ──
        while chunk_count < total_chunks:
            header_bytes = recv_exact(conn, HEADER_SIZE)
            msg_type, seq, payload_len = parse_header(header_bytes)
            payload = recv_exact(conn, payload_len) if payload_len > 0 else b""

            if msg_type == TYPE_REVERSE_REQ:
                chunk_count += 1
                text = payload.decode("ascii", errors="replace")
                reversed_text = text[::-1]
                log(f"[Client-{client_id}] reverseRequest 第{chunk_count}块, len={len(text)} → 反转完成")
                answer = build_packet(TYPE_REVERSE_ANS, seq, reversed_text.encode("ascii"))
                conn.sendall(answer)
            else:
                log(f"[Client-{client_id}] 期望reverseRequest, 收到 type={msg_type:#x}")

        log(f"[Client-{client_id}] 全部 {total_chunks} 块处理完成, filename={filename}")

    except (ConnectionError, ConnectionResetError, struct.error) as e:
        log(f"[Client-{client_id}] 连接异常: {e}")
    finally:
        conn.close()
        log(f"[Client-{client_id}] 连接关闭")


def main():
    if len(sys.argv) != 2:
        print("用法: python reversetcpserver.py <端口>")
        sys.exit(1)

    port = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(10)
    log(f"TCP Reverse Server 启动, 监听端口 {port}")

    client_counter = 0
    try:
        while True:
            conn, addr = server_socket.accept()
            client_counter += 1
            t = threading.Thread(target=handle_client, args=(conn, addr, client_counter), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("服务器已停止")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
