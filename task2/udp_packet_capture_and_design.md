# Task2: UDP Socket Programming — 抓包与设计说明

## 一、程序编译与运行

### 环境要求
- Python 3.7+
- 无需额外依赖库（标准库：`socket`, `struct`, `random`, `sys`, `os`, `time`, `datetime`, `math`）

### 运行方式

**1. 启动服务端：**
```bash
python udpserver.py <端口号> [丢包概率(0~1)] [合法StudentID]
```
示例：`python udpserver.py 9999 0.15` （丢包率15%，非0 StudentID 即合法）

参数：
- `端口号`：UDP 监听端口
- `丢包概率`（可选，默认 0.15）：服务端模拟丢包的概率
- `合法StudentID`（可选，默认非0即合法）：若指定则严格匹配

**2. 启动客户端：**
```bash
python udpclient.py <server_ip> <server_port> <input_file> <StudentID> [pkt_size=80]
```
示例：`python udpclient.py 127.0.0.1 9999 sample.txt 20240001 80`

参数：
- `pkt_size`（可选，默认80）：每包载荷字节数，范围 40~80

## 二、自定义报文格式设计

### 报文结构（Header 13 bytes）

```
┌──────────┬──────────┬──────────┬──────────┬──────────────────┐
│   Type   │   Seq    │   Ack    │  Length  │     Payload      │
│ (1 byte) │(4 bytes) │(4 bytes) │(4 bytes) │   (变长, 0~N)    │
└──────────┴──────────┴──────────┴──────────┴──────────────────┘
```

- **Type (1B):** 报文类型
  - `0x01` — SYN（握手请求，载荷含 StudentID）
  - `0x02` — SYNACK（握手确认）
  - `0x03` — ACK（握手最终确认）
  - `0x04` — DATA（数据报文）
  - `0x05` — DATAACK（数据确认，载荷含 server 系统时间 hh:mm:ss）
  - `0x06` — FIN（挥手请求）
  - `0x07` — FINACK（挥手确认）
- **Seq (4B):** 序列号（网络字节序）
- **Ack (4B):** 确认号（网络字节序）
- **Length (4B):** 载荷长度（网络字节序）

### 各类型报文语义

| 类型 | 方向 | Seq 含义 | Ack 含义 | Payload |
|------|------|----------|----------|---------|
| SYN | C→S | 客户端初始seq | 0 | StudentID(2B, 网络字节序) |
| SYNACK | S→C | 服务端初始seq | 客户端seq+1 | 空 |
| ACK | C→S | 客户端seq+1 | 0 | 空 |
| DATA | C→S | 数据字节偏移 | 0 | 40~80字节载荷 |
| DATAACK | S→C | 0 | 累积确认号 | server系统时间(hh:mm:ss) |
| FIN | C→S | next_seq | 0 | 空 |
| FINACK | S→C | 0 | FIN.seq+1 | 空 |

## 三、协议交互流程

### 3.1 三次握手（模拟 TCP 连接建立）

```
Client                              Server
  |                                   |
  |── SYN (seq=x, payload:StudentID) →|
  |                                   | 校验 StudentID
  |←── SYNACK (seq=y, ack=x+1) ─────|
  |                                   |
  |── ACK (seq=x+1) ────────────────→|
  |                                   |
  |        === 连接建立 ===           |
```

### 3.2 GBN 数据传输

- 窗口大小：固定 400 字节
- 每包载荷：40~80 字节（默认 80），最后一个包可能不足
- 超时时间：300ms
- 接收方：GBN 风格，只接受期望 seq 的包，乱序丢弃
- 发送方：窗口内发送，超时后回退重传

### 3.3 挥手

```
Client                              Server
  |                                   |
  |── FIN ──────────────────────────→|
  |←── FINACK ──────────────────────|
```

## 四、GBN 协议关键实现

### 4.1 窗口管理（chunk 索引）

```python
base      = 0         # 窗口左边界（chunk索引，最小未确认）
next_chunk = 0         # 下一个待发送 chunk
max_pkts  = WINDOW_SIZE // pkt_size  # 窗口最多容纳的报文数
# 发送条件: next_chunk - base < max_pkts
```

### 4.2 发送与日志（严格匹配文档格式）

```python
def send_chunk(chunk_idx):
    byte_start = chunk_idx * pkt_size
    byte_end   = min(byte_start + len(chunks[chunk_idx]) - 1, total_len - 1)
    # 发送 UDP 包...
    n = chunk_idx + 1  # 1-based 编号
    logger.log(f"第{n}个（第{byte_start}~{byte_end}字节）client端已经发送")
```

收到 ACK 后的日志：
```python
logger.log(f"第{n}个（第{byte_start}~{byte_end}字节）server端已经收到，"
           f"RTT是{rtt:.2f} ms, server时间={server_time}")
```

超时重传日志：
```python
logger.log(f"重传第{n}个（第{byte_start}~{byte_end}字节）数据包")
```

### 4.3 累积确认处理

```python
ack_offset = ack  # 累积确认字节偏移
acked_until_chunk = ack_offset // pkt_size
if acked_until_chunk > base:
    # 对 [base, acked_until_chunk) 区间记录 RTT
    base = acked_until_chunk
    # 滑动窗口，发送新包
```

### 4.4 超时重传

```python
if time.time() - timer_start > TIMEOUT:  # 300ms
    for ci in range(base, min(next_chunk, base + max_pkts)):
        # 重传窗口内所有未确认的包
        byte_start = ci * pkt_size
        byte_end = ...
        send(pkt)
        logger.log(f"重传第{n}个（第{byte_start}~{byte_end}字节）数据包")
    timer_start = time.time()
```

### 4.5 服务端丢包模拟与 StudentID 校验

```python
# SYN 载荷中提取 StudentID
student_id = struct.unpack("!H", payload[:2])[0]
if student_id == 0:
    log(f"非法 StudentID, 拒绝连接")
    continue

# 随机丢包
if random.random() < loss_rate:
    continue  # 不发送 ACK
```

### 4.6 服务端 ACK 携带系统时间

```python
now_str = datetime.datetime.now().strftime("%H:%M:%S")
ack_pkt = build_packet(TYPE_DATAACK, 0, ack_num, now_str.encode("ascii"))
sock.sendto(ack_pkt, addr)
```

### 4.7 统计指标

```python
loss_rate = (30 / total_sent) * 100           # 丢包率: 30÷实际发送

max_rtt = max(rtt_samples)                    # 最大RTT (ms)
min_rtt = min(rtt_samples)                    # 最小RTT (ms)
avg_rtt = sum(rtt_samples) / len(samples)     # 平均RTT (ms)
variance = sum((x-avg)^2) / n                 # 方差
std_rtt = math.sqrt(variance)                 # RTT标准差 (ms)
```

## 五、Wireshark 抓包截图

> ⚠️ 请在验收前自行抓包并替换以下占位说明。

**抓包步骤：**
1. 启动 Wireshark，选择 loopback 接口
2. 过滤器：`udp.port == <你的端口号>`
3. 先启动服务端，再启动客户端

**截图要求：**
1. 整体交互截图（SYN→SYNACK→ACK→DATA→DATAACK→…→FIN→FINACK）
2. 自定义报文头部细节截图（13 字节 header hex 解析）
3. 丢包和重传过程截图（同一 seq 的 DATA 多次发送）

## 六、知识点总结

1. **UDP Socket 编程**：`SOCK_DGRAM`, `sendto()`, `recvfrom()`，无连接特性
2. **在 UDP 上模拟 TCP 可靠性**：应用层实现序列号、确认号、重传
3. **GBN（Go-Back-N）协议**：滑动窗口、累积确认、超时回退重传
4. **三次握手/挥手**：SYN/SYNACK/ACK, FIN/FINACK 应用层模拟
5. **超时重传机制**：定时器管理、300ms 超时检测、窗口回退
6. **StudentID 校验**：连接建立阶段身份验证
7. **丢包模拟**：服务端随机不响应，测试 GBN 重传
8. **RTT 统计**：往返时延测量与标准差计算
9. **应用层协议设计**：自定义 13 字节头部，7 种报文类型

## 七、Git URL

> ⚠️ 请在此处填写你的 GitHub / Gitee 仓库地址。
