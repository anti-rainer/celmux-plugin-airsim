# celmux-plugin-airsim

让 AirSIM iOS 客户端拨打 Celmux 的 VoWiFi/VoLTE 线路。

Celmux 管理卡片、IMS 注册和通话，这个进程负责把 AirSIM 的 VoWLAN 协议翻译成 Celmux 的插件 API 调用。它不持有任何卡片状态——线路、通话、短信的每一个问题都问 Celmux。

## 架构位置

```
AirSIM iOS ──Bonjour/HTTP+PCM──> celmux-plugin-airsim ──插件令牌──> Celmux 本体
                                        (独立进程)                    (MU300 等)
```

插件通过 Celmux 设置页安装、启用、配置和授权。它不登录 Celmux：Celmyx 在安装时生成一枚私有令牌，插件用 `Authorization: Bearer` 访问 `/api/plugin-api/airsim/*`。

## 两个不同的密钥

| 密钥 | 谁持有 | 用途 |
|---|---|---|
| `celmux_token` | 插件持有 | 插件 → Celmux 的认证 |
| `pairing_secret` | 插件与手机共有 | 手机 → 插件的 HMAC 签名 |

两者必须分开：共用一个值意味着能连上桥的手机也能改卡片。

`pairing_secret` 是 32 字节，base64url 编码（带不带 padding 都行）。

## 配置

全部由 Celmux 在启动插件时以下发环境变量提供，插件自己不读数据库：

| 键 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `celmux_token` | ✓ | | Celmux 安装时生成的插件令牌 |
| `celmux_host` | | `127.0.0.1:8080` | Celmux API 地址 |
| `pairing_secret` | ✓ | | 手机配对密钥，base64url，≥32 字节 |
| `agent_id` | | `celmux` | 手机列表里显示的名字 |
| `control_port` | | `8642` | 控制接口端口 |
| `pcm_port` | | `8643` | PCM 音频端口 |
| `advertise` | | `true` | 是否做 Bonjour 广播 |

## 它讲什么协议

**发现**：Bonjour `_airsim-vowlan._tcp`，TXT 记录带 `host` / `control_port` / `pcm_port`。

**认证**：每个控制请求都签名。

```
canonical = METHOD\npath\nsha256hex(body)\ntimestamp\nnonce
signature = base64url(HMAC-SHA256(pairing_secret, canonical))
```

请求头 `x-airsim-vowlan-signature` / `x-airsim-vowlan-timestamp` / `x-airsim-vowlan-nonce`。时间戳窗口 30 秒，nonce 在窗口内去重。

**控制面**：

| 路由 | 说明 |
|---|---|
| `GET /healthz` | 不签名，仅探活 |
| `GET /v1/health` | 返回 agent_id 与 HMAC 证明 |
| `GET /v1/devices/status` | 线路列表，投影成"设备" |
| `POST /v2/commands/enqueue` | `{"command":"dial","device_id":..,"number":..}` |
| `POST /v2/calls/{id}/actions` | answer / reject / hangup |

**设备视图**：Celmux 用线路，AirSIM 用设备。设备自有线路就是那台设备；N 待下的 Profile 线路显示为 `设备名 · 运营商`，否则同一台设备的多条线路在手机上无法区分。

## 已实现 / 未实现

已实现：私有令牌认证、Bonjour 广播、健康检查证明、设备列表、拨号、挂断、拒接。

未实现：

- **接听**（返回 501）——接听必须在应答时选定音频通路，而每种通路都要求一个本桥没有的音频端点。谎报成功会让手机显示已接通却没有声音，所以它直接说明不可用。
- **PCM 音频网关**——`AIRSIMPCM1` / `AIRSIMREADY` 握手与 20ms 帧循环。

## 构建

```bash
cargo build --release
cargo test
```

## 许可

PolyForm Noncommercial 1.0.0
