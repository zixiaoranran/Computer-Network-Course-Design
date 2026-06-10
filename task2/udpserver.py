"""
UDP Server (GBN Receiver) — 2026春计网课程实习 Task2
功能：
  - 模拟 TCP 三次握手建立连接（SYN携带StudentID校验）
  - 接收客户端数据，模拟 GBN 协议接收方行为
  - 累积确认（返回期望的下一个 seq）
  - ACK 中携带服务端系统时间（hh:mm:ss）
  - 模拟 client→server 方向的丢包（随机不发送 ACK）

自定义 UDP 报文格式 (Header 13 bytes):
  - Type:     1 byte  (0x01=SYN, 0x02=SYNACK, 0x03=ACK, 0x04=DATA, 0x05=DATAACK, 0x06=FIN, 0x07=FINACK)
  - Seq:      4 bytes (unsigned int, network byte order)
  - Ack:      4 bytes (unsigned int, network byte order)
  - Length:   4 bytes (unsigned int, network byte order)
  - Payload:  变长
"""

import socket
import struct
import sys
import datetime
import random

# ── 报文类型 ──
TYPE_SYN     = 0x01
TYPE_SYNACK  = 0x02
TYPE_ACK     = 0x03
TYPE_DATA    = 0x04
TYPE_DATAACK = 0x05
TYPE_FIN     = 0x06
TYPE_FINACK  = 0x07

HEADER_FORMAT = "!B I I I"   # Type(1) + Seq(4) + Ack(4) + Len(4)
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

WINDOW_SIZE = 400
XOR_KEY     = 0x5A3C  # XOR 密钥


def log(msg: str):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{now}] {msg}", flush=True)


def server_time_str() -> str:
    """返回 hh:mm:ss 格式的服务端系统时间"""
    return datetime.datetime.now().strftime("%H:%M:%S")


def build_packet(msg_type: int, seq: int, ack: int, payload: bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, msg_type, seq, ack, len(payload))
    return header + payload


def parse_packet(data: bytes):
    """解析报文，返回 (type, seq, ack, length, payload) 或 None"""
    if len(data) < HEADER_SIZE:
        return None
    t, s, a, l = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:HEADER_SIZE + l]
    return t, s, a, l, payload


def main():
    if len(sys.argv) < 2:
        print("用法: python udpserver.py <端口> [丢包概率(0~1, 默认0.15)]")
        sys.exit(1)

    port = int(sys.argv[1])
    loss_rate = float(sys.argv[2]) if len(sys.argv) >= 3 else 0.15

    log(f"UDP Server 启动, 端口 {port}, 丢包概率={loss_rate*100:.0f}%")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))

    total_received = 0
    total_dropped  = 0
    total_acked    = 0

    # 客户端状态: addr -> {state, expected_seq, received_data}
    client_state = {}

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            result = parse_packet(data)
            if result is None:
                continue

            msg_type, seq, ack, payload_len, payload = result

            # ========== 三次握手 ==========
            if msg_type == TYPE_SYN:
                # SYN 载荷包含 XORed StudentID (2 bytes)
                if payload_len < 2:
                    log(f"[{addr}] SYN 载荷过短, 拒绝")
                    continue
                xor_id = struct.unpack("!H", payload[:2])[0]

                # XOR 反算验证
                raw_sid = (xor_id ^ XOR_KEY) & 0xFFFF
                if raw_sid < 0 or raw_sid > 9999:
                    log(f"[{addr}] 非法 StudentID(收到0x{xor_id:04X}, XOR还原={raw_sid}), 拒绝连接")
                    continue

                log(f"[{addr}] 收到 SYN seq={seq}, XORedID=0x{xor_id:04X}, 学号后4位={raw_sid}")
                server_seq = random.randint(1000, 9999)
                client_state[addr] = {
                    "state": "established",
                    "expected_seq": 0,
                    "received_data": {},
                    "student_id": raw_sid,
                }
                synack = build_packet(TYPE_SYNACK, server_seq, seq + 1, b"")
                sock.sendto(synack, addr)
                log(f"[{addr}] 发送 SYNACK seq={server_seq} ack={seq + 1}")

            elif msg_type == TYPE_ACK:
                if addr in client_state and client_state[addr].get("state") == "established":
                    log(f"[{addr}] 收到 ACK (握手完成)")

            # ========== 数据传输 ==========
            elif msg_type == TYPE_DATA:
                if addr not in client_state:
                    continue

                total_received += 1
                expected_seq = client_state[addr]["expected_seq"]

                # 模拟丢包：随机不响应
                if random.random() < loss_rate:
                    total_dropped += 1
                    log(f"[{addr}] DATA seq={seq} ← 模拟丢包, 不回复ACK")
                    continue

                # GBN 接收方：只接受期望的 seq
                if seq == expected_seq:
                    client_state[addr]["received_data"][seq] = payload
                    client_state[addr]["expected_seq"] += len(payload)

                    # 累积确认，携带服务端系统时间
                    ack_num = client_state[addr]["expected_seq"]
                    now_str = server_time_str()
                    ack_pkt = build_packet(TYPE_DATAACK, 0, ack_num, now_str.encode("ascii"))
                    sock.sendto(ack_pkt, addr)
                    total_acked += 1

                    log(f"[{addr}] DATA seq={seq}, len={len(payload)} → ACK={ack_num}, "
                        f"server_time={now_str}")
                else:
                    # 乱序：发送累积ACK
                    now_str = server_time_str()
                    ack_pkt = build_packet(TYPE_DATAACK, 0, expected_seq, now_str.encode("ascii"))
                    sock.sendto(ack_pkt, addr)
                    log(f"[{addr}] DATA seq={seq} 乱序(期望{expected_seq}) → ACK={expected_seq}")

            # ========== 挥手 ==========
            elif msg_type == TYPE_FIN:
                log(f"[{addr}] 收到 FIN seq={seq}")
                finack = build_packet(TYPE_FINACK, 0, seq + 1, b"")
                sock.sendto(finack, addr)
                log(f"[{addr}] 发送 FINACK")

                if addr in client_state:
                    received = client_state[addr]["received_data"]
                    all_data = b"".join(received[k] for k in sorted(received.keys()))
                    output = all_data.decode("ascii", errors="replace")
                    log(f"[{addr}] 完整数据: {len(output)} 字符")
                    log(f"[{addr}] === 收到{total_received}, 丢包{total_dropped}, 确认{total_acked} ===")
                    del client_state[addr]

    except KeyboardInterrupt:
        log("服务器已停止")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
