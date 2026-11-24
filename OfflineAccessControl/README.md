# OfflineAccessControl —— 离线敏感数据访问控制参考实现

面向「海外工地、长期断网、手机可能丢失、员工可能离职」场景的 iOS Swift 实现。
目标：**离线多天仍能正常工作，但密钥与用户身份、设备状态绑定；离线超时或远程吊销后，
本地缓存的敏感文件在密码学意义上不可读。**

## 1. 先承认安全边界

一台**永久离线且已被越狱**的设备，在密码学上无法被即时吊销——手机收不到任何消息，
本地所有校验逻辑都可能被 patch。本方案不承诺「发一条指令就能让离线手机立刻报废」，
而是做到：

1. 把失陷暴露窗口压缩到**最后一张租约的有效期**（建议 7~14 天），而不是无限期；
2. 让攻击者无法通过改时间、关机、重放旧票据来**延长**这个窗口；
3. 让任何一次短暂联网（借热点、路过有信号的营地）都能完成吊销同步；
4. 即使整份 App 沙盒被拷走，没有 Secure Enclave 内的私钥也解不出任何文件。

## 2. 架构总览

```
                         ┌──────────────────── 服务端（在线，仅刷新时需要）────────────────────┐
                         │  登录认证(MFA) → 设备注册校验 → 租约签发(签名密钥在 KMS/HSM)        │
                         │  吊销名单签名发布（静态文件，挂 CDN/对象存储）                       │
                         └───────────────┬───────────────────────────────┬────────────────────┘
                                         │ ① 离线租约 OfflineLease（签名）  │ ② 签名吊销名单（拉取）
                                         ▼                                 ▼
  App 沙盒 / Keychain（ThisDeviceOnly）
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │ OfflineAccessManager（门面）                                                            │
  │                                                                                         │
  │  DeviceIdentity        OfflineLease        TimeGuardian        RevocationRegistry       │
  │  SE P-256 双密钥       服务器签名票据       双时钟防回拨          版本化签名名单            │
  │  (签名 + ECDH)         含 ECIES(KEK)        墙钟高水位线          设备/用户/租约三级吊销     │
  │                                              + 单调额度                                      │
  │                                       │                                                  │
  │                                       ▼ unlock() 全部本地校验通过后                        │
  │                                 AccessSession（KEK 只在内存）                             │
  │                                       │ seal / open                                       │
  │                                       ▼                                                  │
  │                                 FileVault：每文件 HKDF 派生 DEK + AES-GCM                │
  └───────────────────────────────────────────────────────────────────────────────────────────┘
```

### 密钥分层

| 密钥 | 生命周期 | 存放位置 |
|---|---|---|
| 设备签名/ECDH 私钥（P-256） | 设备注册时生成，长期 | **Secure Enclave**（模拟器/无 SE 设备降级为 Keychain 软件密钥 + 生物识别） |
| KEK（密钥加密密钥） | 服务端生成，随租约按 epoch 轮换 | 从不在设备落盘；ECIES 信封投递，解锁后只存在于会话内存 |
| DEK（每文件数据密钥） | 不存储，按需确定性派生 | `HKDF-SHA256(KEK, salt="dek-v1", info=fileId)` |
| 服务端租约签名密钥 | 长期 | 服务端 KMS/HSM；App 只内置**公钥** |

「离线超时自动失效」在文件层的落点不是删文件，而是**让 KEK 不可达**：租约失效后
无法通过校验、无法解包 KEK，磁盘上的密文就只是一堆随机字节。

## 3. 四个核心难点的解法

### 3.1 连续多天断网仍要工作 → 租约（Lease）模式

离线期间不做任何网络请求，全部安全判定只依赖一张服务器预先签名的票据
（`LeasePayload`）：用户 id、设备 id、绝对到期时刻、单调时钟额度、epoch、ECIES 包裹的 KEK。
票据在联网刷新时签发，TTL 按业务能接受的最长暴露窗口设定（见 §6 参数建议）。

### 3.2 时间可以被人为调整 → 双时钟交叉校验（`TimeGuardian`）

单靠任何一条时钟都会被绕过，因此用两条互相兜底：

- **墙钟 + 高水位线**：每次检查点记录见过的最大墙钟时间（存 Keychain），
  回拨超过 5 分钟抖动容忍即判 `clockTamperingDetected`；
- **单调时钟（`CLOCK_MONOTONIC_RAW`）+ 累计额度**：该时钟不受 settimeofday/NTP 影响，
  且包含休眠时长（息屏放口袋也计时，无法靠锁屏白嫖）。冻结墙钟的攻击者，
  累计使用时长超额度仍会被锁；
- **重启识别（`kern.boottime`）**：单调时钟重启归零，关机跨越的时间它看不见。
  bootId 变化时把已结束开机周期的耗时一次性、幂等地入账；关机期间墙钟正常流逝
  会撞绝对到期，回拨墙钟则撞高水位线。

记账模型为「已完成开机周期累计 + 当前开机周期耗时」，保证同一段时间不会被重复计算。

### 3.3 吊销指令可能永远送不到 → 拉取模型 + TTL 兜底 + epoch 前向保密

- 吊销名单是**服务器签名的静态文件**（几十 KB），挂 CDN/对象存储，不依赖 App 后端在线。
  App 在**任何一次**能联网的时刻主动拉取，拉不到就维持旧名单 + 租约 TTL 兜底，
  安全性不回退；
- 名单带单调递增 `version`，旧版本无法覆盖新版本（防重放「还没吊销我」的老名单）；
- 支持三级吊销：设备 id、用户 id（整人停用）、租约版本（精确作废某张票据）；
- 命中吊销立即自毁本地租约与时间状态；活跃会话的**下一次文件操作**实时复检也会被拒；
- **epoch 前向保密**：重新签发租约时服务端轮换 KEK 并递增 epoch，旧租约解不开
  新 epoch 的文件——离职员工即使藏了一张未到期的旧租约，也读不到轮换后的新数据。

### 3.4 设备/身份绑定 → Secure Enclave + ECIES

- 设备注册时在 SE 内生成 P-256 签名与 ECDH 两把密钥，配置 `.biometryAny` +
  `.privateKeyUsage`：每次私钥操作都必须过生物识别，且运算在安全隔区内完成，
  系统主核拿不到密钥本体；
- KEK 用设备 ECDH 公钥做 ECIES（临时 ECDH + HKDF + AES-GCM，AAD 绑定设备 id 与上下文标签）。
  只有那台设备的 SE 私钥能解包；
- Keychain 全部使用 `ThisDeviceOnly`，不进 iCloud Keychain、不进加密备份，
  整机备份恢复到另一台设备时密钥不会迁移；
- 租约内的 userId/deviceId 与本机身份记录强匹配，签发给别人设备的票据直接拒绝。

## 4. 模块说明

| 文件 | 职责 |
|---|---|
| `DeviceIdentity.swift` | SE/软件双密钥的生成、持久化、ECDH 与设备 attestation 签名 |
| `ECIES.swift` | KEK 的 ECIES 信封包裹/解包（P-256 + HKDF + AES-GCM） |
| `Lease.swift` | 租约载荷、规范化编码、服务器签名与客户端验签 |
| `Revocation.swift` | 签名吊销名单的版本防重放、三级吊销查询 |
| `TimeGuardian.swift` | 双时钟防回拨、重启识别、单调额度记账、绝对到期 |
| `FileVault.swift` | 每文件 DEK 派生与 AES-GCM 加解密，fileId 作为 AAD |
| `OfflineAccessManager.swift` | 门面：装租约、解锁、会话复检、检查点、吊销更新、自毁 |
| `KeychainSecureStorage.swift` | 生产 Keychain 实现（含生物识别 ACL） |
| `SecureStorage.swift` | 存储抽象 + 内存实现（测试用） |
| `ClockSource.swift` | 时钟抽象、系统实现、`FakeClock`（可拨时间/模拟重启） |
| `HKDFHelper.swift` | RFC 5869 HKDF（兼容旧系统，不依赖新版便捷 API） |

## 5. 使用方式

### 5.1 首次登录与设备注册（需要联网）

```swift
let storage = KeychainSecureStorage(service: "com.company.oac")
let identity = DeviceIdentity(storage: storage)
let ticket = try identity.enroll(userId: user.id, deviceId: device.id)
// 把 ticket（两把公钥 + 设备信息）经 MFA 认证的登录通道发给服务端，
// 服务端校验后绑定，并把两把公钥入库。
```

### 5.2 服务端签发租约（伪代码，服务端实现）

```
kek = 随机 32 字节（按 epoch 管理）
envelope = ECIES.wrap(kek, 设备ECDH公钥, deviceId)
payload  = LeasePayload(leaseVersion 自增, userId, deviceId, epoch,
                        expiresAt = now + TTL,
                        monotonicBudgetSeconds = 预算,
                        issuedAt = now, wrappedKEK = envelope)
lease    = 用 KMS 签名密钥对规范化 payload 做 ECDSA 签名
```

### 5.3 客户端安装租约并离线使用

```swift
let verifier = try LeaseVerifier(publicKeyRaw: 内置的服务器公钥)
let manager = OfflineAccessManager(storage: storage, identity: identity, verifier: verifier)

try manager.installLease(lease)                 // 联网刷新时
let session = try manager.unlock()              // 离线解锁（SE 弹生物识别）
let sealed = try session.seal(fileId: "drawings/a.pdf", plaintext: data)
let data   = try session.open(sealed)
```

### 5.4 接入 App 生命周期与联网机会

```swift
// scenePhase == .background：落检查点并锁定，保证杀进程后额度不丢、KEK 立即释放
try manager.checkpoint()
manager.lock()

// 任何一次网络可达（哪怕只是 CDN）：拉签名名单 + 尝试刷新租约
let list: RevocationList = try await cdn.get("/revocation/latest.json")
try manager.updateRevocationList(list)
if let newLease = try? await api.refreshLease(challengeSignature: ...) {
    try manager.installLease(newLease)
}
```

### 5.5 验证程序

本环境无 Xcode/XCTest，仓库用一个可执行 target 承载 22 个端到端场景（含改时间、
冻结时钟、模拟重启、重放、伪造签名、epoch 轮换等）：

```bash
swift run oac-verify
# == 结果：22 通过，0 失败 ==
```

接入 Xcode 工程时，可把 `Sources/OACVerify` 中的场景平移为 XCTest（断言一一对应）。

## 6. 参数与策略建议

| 参数 | 建议 | 取舍 |
|---|---|---|
| 租约 TTL（绝对有效期） | 7~14 天 | 越短越安全但刷新压力越大；应 ≥ 工地单次最长预期断网时长 |
| 单调时钟预算 | 略大于 TTL 对应的总时长（如 TTL 7 天给 8~9 天额度） | 它是「冻结墙钟」攻击的兜底，正常使用不应被它误杀；需要更严格可独立收紧 |
| 墙钟抖动容忍 | 300 秒 | 覆盖 NTP 校时与跨时钟源误差，太小会误杀 |
| 后台锁定延迟 | 30~120 秒或立即 | 配合 `WhenUnlockedThisDeviceOnly`，锁屏后 Keychain 不可读 |
| epoch 轮换周期 | 每次租约刷新或每次离职/报失事件 | 轮换后旧密文需随同步通道重发新 epoch 版本 |
| 数据文件保护 | 本层加密之外，目录再开 `NSFileProtectionComplete` | 纵深防御：锁屏后系统层也不可读 |

### 服务端配套要求

1. 租约签名密钥放 HSM/KMS，开启审计；签名公钥随 App 发布（可做证书 pinning）；
2. `leaseVersion` 用服务端单调序列，刷新接口校验设备挑战签名（`signChallenge`），
   防止替别人刷租约；
3. 吊销名单发布到高可用 CDN，客户端用 `If-None-Match` 轻量轮询；
4. 离职/报失工单触发：吊销名单更新 + 下次该用户/设备刷新时强制 epoch 轮换；
5. MDM 层面建议开启「managed apps 不允许备份、不允许跨设备恢复」。

## 7. 残余风险与诚实说明

1. **越狱 + 永久离线 + 全时钟伪造**：攻击者若同时 hook 单调时钟、伪造 bootId、
   冻结墙钟并 patch 掉本地校验，理论上可让时间线停摆。此时防线退化为
   「SE 生物识别 + 短 TTL」，暴露窗口为最后一张租约的有效期，无法再被延长；
2. **SE 生物识别可被设备密码替代**：掌握设备锁屏密码的攻击者（如离职前未交还的
   员工本人）可以通过密码重设生物识别。高安全岗位应配合强设备密码策略与 MDM；
3. **越狱设备上的内存读取**：解锁会话期间 KEK 在内存中。已通过「后台即锁定 +
   最小化会话存活时间 + SymmetricKey 安全内存」收窄窗口，但无法完全消除；
4. **吊销的最终时延下限 = 租约 TTL**（对永久离线设备）。这是该类问题的物理下限，
   任何纯客户端方案都无法突破，只能靠短 TTL + 频繁联网机会逼近；
5. 软件密钥降级路径（模拟器/无 SE 的 Mac，如 CI）安全性弱于 SE，生产构建应通过
   `DeviceIdentity.isSecureEnclaveAvailable` 断言必须走 SE，拒绝在无 SE 设备上启用。

## 8. 平台与依赖

- iOS 15+ / macOS 12+；仅使用系统框架（CryptoKit、Security、Darwin），无第三方依赖；
- Swift 6，全部跨线程状态由 `NSLock` 保护，敏感存储走 `Sendable` 抽象；
- 已在 Swift 6.3 开源工具链（macOS）编译并通过全部 22 个场景验证。
