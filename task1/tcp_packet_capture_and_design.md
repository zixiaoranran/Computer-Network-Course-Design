# Task1: TCP Socket Programming — 抓包与设计说明

## 一、程序编译与运行

### 环境要求
- Python 3.7+
- 无需额外依赖库（标准库：`socket`, `struct`, `threading`, `random`, `sys`, `os`, `time`, `datetime`）

### 运行方式

**1. 启动服务端：**
```bash
python reversetcpserver.py <端口号>
```
示例：`python reversetcpserver.py 8888`

**2. 启动客户端：**
```bash
python reversetcpclient.py <server_ip> <server_port> <Lmin> <Lmax> <chunk_seed> <input_file> <StudentID>
```
示例：`python reversetcpclient.py 127.0.0.1 8888 10 50 42 sample.txt 20240001`

参数说明：
- `Lmin`: 每段最小长度（字节）
- `Lmax`: 每段最大长度（字节）
- `chunk_seed`: 随机种子，用于确定分块方案（保证验收时可复现）
- `StudentID`: 学号（2字节范围 1~65535）

## 二、自定义报文格式设计

### 报文结构（Header 9 bytes）

```
┌──────────┬──────────────┬──────────────┬──────────────────┐
│  Type    │   Sequence   │   Length     │     Payload      │
│ (1 byte) │  (4 bytes)   │  (4 bytes)   │   (变长, 0~N)    │
└──────────┴──────────────┴──────────────┴──────────────────┘
```

- **Type (1B):** 报文类型标识
  - `0x01` — Initialization（初始化）
  - `0x02` — agree（同意建立连接）
  - `0x03` — reverseRequest（反转请求）
  - `0x04` — reverseAnswer（反转应答）
- **Sequence (4B):** 报文序号，网络字节序
- **Length (4B):** 载荷长度，网络字节序

### Initialization 报文 Payload 结构

```
┌──────────────┬──────────────┬───────────────┬──────────────┐
│  StudentID   │  chunk_seed  │  total_chunks │   filename   │
│  (2 bytes)   │  (4 bytes)   │  (4 bytes)    │  (变长 UTF-8) │
└──────────────┴──────────────┴───────────────┴──────────────┘
```

- **StudentID (2B):** 学号，网络字节序，服务端校验非0
- **chunk_seed (4B):** 分块随机种子，网络字节序
- **total_chunks (4B):** 总块数，网络字节序
- **filename (变长):** UTF-8 编码的文件名

### 各类型报文语义

| 类型 | 方向 | Payload 内容 |
|------|------|-------------|
| Initialization (0x01) | Client→Server | StudentID + chunk_seed + total_chunks + filename |
| agree (0x02) | Server→Client | 空 |
| reverseRequest (0x03) | Client→Server | 待反转的 ASCII 文本段 |
| reverseAnswer (0x04) | Server→Client | 反转后的 ASCII 文本段 |

## 三、交互流程

```
Client                                      Server
  │                                           │
  │── Initialization(type=1, StudentID,     │           │   chunk_seed, total_chunks, filename) ──→│
  │                                           │ 校验StudentID
  │←── agree(type=2) ──────────────────────│
  │                                           │
  │── reverseRequest(type=3, seq=1, seg₁) ──→│
  │←── reverseAnswer(type=4, seq=1, rev₁) ──│
  │                                           │
  │── reverseRequest(type=3, seq=2, seg₂) ──→│
  │←── reverseAnswer(type=4, seq=2, rev₂) ──│
  │                                           │
  │              ... (共total_chunks块)         │
  │                                           │
  │  [连接关闭]                                │
```

## 四、Wireshark 抓包截图

> ⚠️ 请在验收前自行抓包并替换以下占位说明。

**抓包步骤：**
1. 启动 Wireshark，选择 loopback 接口
2. 过滤器：`tcp.port == <你的端口号>`
3. 先启动服务端，再启动客户端
4. 传输完成后停止抓包

**截图要求：**
1. Wireshark 主界面截图（能看到 TCP 三次握手和所有报文）
2. Follow TCP Stream 截图（清晰显示 Initialization→agree→reverseRequest→reverseAnswer 的交互过程）
3. 报文头部细节截图（选中某个 payload，底部 hex 面板显示 9 字节 header）

## 五、实现关键点及代码

### 5.1 报文构造与解析

```python
HEADER_FORMAT = "!B I I"   # Type + Seq + Len，! 表示网络字节序
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # 9 bytes

def build_packet(msg_type, seq, payload_bytes):
    header = struct.pack(HEADER_FORMAT, msg_type, seq, len(payload_bytes))
    return header + payload_bytes
```

### 5.2 Initialization 载荷（含 StudentID）

```python
INIT_PREFIX_FORMAT = "!H I I"  # StudentID(2B) + chunk_seed(4B) + total_chunks(4B)
init_prefix = struct.pack(INIT_PREFIX_FORMAT, student_id, chunk_seed, total_chunks)
init_payload = init_prefix + filename.encode("utf-8")
sock.sendall(build_packet(TYPE_INITIALIZATION, 0, init_payload))
```

### 5.3 服务端 StudentID 校验

```python
student_id, chunk_seed, total_chunks = struct.unpack(INIT_PREFIX_FORMAT, payload[:10])
if student_id == 0:
    log(f"非法的StudentID={student_id}, 拒绝连接")
    conn.close()
    return
```

### 5.4 使用 chunk_seed 可复现分块

```python
random.seed(chunk_seed)   # 验收时给出相同 seed 可复现分块结果
while pos < total_len:
    seg_len = random.randint(Lmin, Lmax)
    seg_len = min(seg_len, total_len - pos)
    segments.append(content[pos:pos + seg_len])
    pos += seg_len
```

### 5.5 服务端多线程并发

```python
while True:
    conn, addr = server_socket.accept()
    client_counter += 1
    t = threading.Thread(target=handle_client, args=(conn, addr, client_counter), daemon=True)
    t.start()
```

### 5.6 精确接收（TCP 流协议边界处理）

```python
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("连接已关闭")
        data += chunk
    return data
```

### 5.7 运行日志

日志同时输出控制台和 `run_log.txt`，时间戳精确到毫秒，与 Wireshark 抓包可互印证。

## 六、知识点总结

1. **TCP Socket 编程**：socket() / bind() / listen() / accept() / connect() / sendall() / recv()
2. **TCP 流协议边界处理**：应用层用"固定头部 + Length"界定消息边界
3. **自定义应用层协议设计**：4 种报文类型、固定头部结构、StudentID 校验
4. **网络字节序**：`struct.pack("!...")` 大端序跨平台兼容
5. **多线程并发**：`threading.Thread` 处理多个客户端
6. **可复现随机分块**：`random.seed(chunk_seed)` 保证验收时结果一致
7. **异常处理**：ConnectionError, ConnectionResetError, TimeoutError

## 七、Git URL

> ⚠️ 请在此处填写你的 GitHub / Gitee 仓库地址。
