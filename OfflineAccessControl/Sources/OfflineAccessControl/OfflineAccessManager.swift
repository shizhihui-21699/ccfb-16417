import Foundation
import CryptoKit

/// 一次解锁后的访问会话。
///
/// KEK 只存在于会话对象内存中：锁屏、主动锁定、租约失效、命中吊销时会话被释放，
/// KEK 随之不可达。Swift `SymmetricKey` 由 libswiftCoreCrypto 管理在安全内存中，
/// 不要把它的 `withUnsafeBytes` 内容拷贝进普通 Data 长期持有。
public final class AccessSession: @unchecked Sendable {
    /// 模块内可见以便测试；业务代码不应直接触碰 KEK，只应调用 seal/open。
    let kek: SymmetricKey
    public let epoch: Int
    private weak var manager: OfflineAccessManager?
    private let stateLock = NSLock()

    init(kek: SymmetricKey, epoch: Int, manager: OfflineAccessManager) {
        self.kek = kek
        self.epoch = epoch
        self.manager = manager
    }

    /// 每次文件操作前的实时复检：时钟状态 + 吊销名单。
    /// 不依赖网络，全部是本地密码学/状态校验。
    private func recheck() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard let manager else { throw AccessControlError.sessionLocked }
        try manager.validateActiveSession()
    }

    public func seal(fileId: String, plaintext: Data) throws -> SealedFile {
        try recheck()
        return try FileVault.seal(fileId: fileId, plaintext: plaintext, kek: kek, epoch: epoch)
    }

    public func open(_ sealed: SealedFile) throws -> Data {
        try recheck()
        // 跨 epoch 的文件用当前 KEK 必然认证失败——密钥轮换后的前向保密落点
        return try FileVault.open(sealed, kek: kek)
    }
}

/// 离线访问控制的门面。建议在 App 内以单例方式持有，并接入 SwiftUI `scenePhase`：
/// `.background` 时调 ``checkpoint()`` 并在短延迟后 ``lock()``。
public final class OfflineAccessManager: @unchecked Sendable {
    private let storage: SecureStorage
    private let identity: DeviceIdentity
    private let guardian: TimeGuardian
    private let revocation: RevocationRegistry
    private let verifier: LeaseVerifier
    private let leaseKey: String

    private let stateLock = NSLock()
    private var activeLease: OfflineLease?
    private weak var session: AccessSession?

    public init(
        storage: SecureStorage,
        identity: DeviceIdentity,
        verifier: LeaseVerifier,
        clock: ClockSource = SystemClockSource(),
        leaseKey: String = "oac.lease.v1",
        timeStateKey: String = "oac.time-state.v1",
        revocationKey: String = "oac.revocation.v1",
        allowedClockSkew: TimeInterval = 300
    ) {
        self.storage = storage
        self.identity = identity
        self.verifier = verifier
        self.leaseKey = leaseKey
        self.guardian = TimeGuardian(
            storage: storage,
            clock: clock,
            storageKey: timeStateKey,
            allowedSkew: allowedClockSkew
        )
        self.revocation = RevocationRegistry(
            storage: storage,
            verifier: verifier,
            storageKey: revocationKey
        )
    }

    // MARK: - 租约生命周期

    /// 安装服务器新签发的租约（联网刷新时调用）。
    ///
    /// 校验链：签名 → 身份绑定 → 版本防重放 → 吊销状态 → 重建时间基线。
    /// 新 epoch 的租约安装后，旧 epoch 密文对新会话不可读（前向保密），
    /// 服务器应在同一轮同步里下发新 epoch 下的文件密文。
    public func installLease(_ lease: OfflineLease) throws {
        try verifier.verify(lease: lease)
        try assertIdentityMatches(lease.payload)

        stateLock.lock()
        let existing = try loadLeaseLocked()
        stateLock.unlock()

        if let existing, lease.payload.leaseVersion <= existing.payload.leaseVersion {
            // 旧租约重放：拒绝。攻击者无法拿一张历史上合法的长 TTL 租约替换当前短租约
            throw AccessControlError.revocationVersionStale
        }

        if try revocation.isRevoked(lease: lease) {
            throw AccessControlError.deviceRevoked
        }

        try storage.write(
            leaseKey,
            data: JSONEncoder.iso8601.encode(lease),
            options: []
        )
        try guardian.resetBaseline(using: lease.payload)
        stateLock.lock()
        activeLease = lease
        stateLock.unlock()
    }

    /// 解锁：离线场景的主入口。全程无网络。
    ///
    /// 顺序经过：本地租约存在 → 服务器签名有效 → 身份绑定 → 未被吊销
    /// → 双时钟状态有效（未回拨、未过期、额度未耗尽）→ SE/生物识别解包 KEK。
    /// 任何一环失败都返回明确错误，且不会留下半初始化会话。
    public func unlock() throws -> AccessSession {
        stateLock.lock()
        let lease = try loadLeaseLocked()
        stateLock.unlock()
        guard let lease else { throw AccessControlError.leaseMissing }

        try verifier.verify(lease: lease)
        try assertIdentityMatches(lease.payload)

        if try revocation.isRevoked(lease: lease) {
            // 命中吊销：立即销毁本地租约与时间状态，避免被绕过逻辑继续使用
            try wipeLocalSecretsLocked()
            throw AccessControlError.deviceRevoked
        }

        // 只读评估先行；通过后再落检查点
        try guardian.evaluate(against: lease.payload)

        let record = try identity.currentRecord()
            .unwrapOrThrow(AccessControlError.identityMismatch)

        // SE 场景：这一步系统会弹生物识别，ECDH 在安全隔区内完成
        let kekData = try KeyWrapping.unwrap(
            envelope: lease.payload.wrappedKEK,
            identity: identity,
            deviceId: record.deviceId
        )
        let kek = SymmetricKey(data: kekData)

        try guardian.checkpoint(against: lease.payload)

        let newSession = AccessSession(kek: kek, epoch: lease.payload.epoch, manager: self)
        stateLock.lock()
        activeLease = lease
        session = newSession
        stateLock.unlock()
        return newSession
    }

    /// 主动锁定 / 场景切后台时调用：释放会话与内存中的 KEK。
    public func lock() {
        stateLock.lock()
        session = nil
        stateLock.unlock()
    }

    public var isUnlocked: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return session != nil
    }

    /// App 进入后台、场景切换时落一次时间检查点，保证杀进程后累计额度不丢。
    public func checkpoint() throws {
        stateLock.lock()
        let lease = try loadLeaseLocked()
        stateLock.unlock()
        guard let lease else { return }
        try guardian.checkpoint(against: lease.payload)
    }

    /// 拉取到新的签名吊销名单时调用（任何一次联网机会都可以做）。
    public func updateRevocationList(_ list: RevocationList) throws {
        try revocation.apply(list)
        // 若新名单直接命中当前设备，立刻自毁
        stateLock.lock()
        let lease = try loadLeaseLocked()
        stateLock.unlock()
        if let lease, try revocation.isRevoked(lease: lease) {
            try wipeLocalSecrets()
        }
    }

    /// 当前离线状态（供 UI 展示剩余有效期与额度）。
    public func offlineStatus(clock: ClockSource = SystemClockSource()) throws -> OfflineStatus {
        stateLock.lock()
        let lease = try loadLeaseLocked()
        stateLock.unlock()
        guard let lease else { throw AccessControlError.leaseMissing }
        let used = try guardian.monotonicUsed()
        let p = lease.payload
        return OfflineStatus(
            expiresAt: p.expiresAt,
            secondsUntilExpiry: p.expiresAt.timeIntervalSince(clock.wallTime()),
            monotonicBudget: p.monotonicBudgetSeconds,
            monotonicUsed: used,
            monotonicRemaining: max(0, p.monotonicBudgetSeconds - used),
            epoch: p.epoch,
            revoked: (try? revocation.isRevoked(lease: lease)) ?? false
        )
    }

    /// 注销 / 退厂：清除全部本地敏感材料。
    public func wipeLocalSecrets() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        try wipeLocalSecretsLocked()
    }

    // MARK: - session re-check（内部）

    func validateActiveSession() throws {
        stateLock.lock()
        let lease = try loadLeaseLocked()
        let hasSession = session != nil
        stateLock.unlock()

        guard hasSession, let lease else { throw AccessControlError.sessionLocked }
        try verifier.verify(lease: lease)
        if try revocation.isRevoked(lease: lease) {
            try wipeLocalSecrets()
            throw AccessControlError.deviceRevoked
        }
        try guardian.evaluate(against: lease.payload)
    }

    // MARK: - internals

    private func assertIdentityMatches(_ payload: LeasePayload) throws {
        guard let record = identity.currentRecord() else {
            throw AccessControlError.identityMismatch
        }
        guard record.userId == payload.userId, record.deviceId == payload.deviceId else {
            throw AccessControlError.identityMismatch
        }
    }

    private func loadLeaseLocked() throws -> OfflineLease? {
        if let activeLease { return activeLease }
        guard let data = try storage.read(leaseKey) else { return nil }
        let lease = try JSONDecoder.iso8601.decode(OfflineLease.self, from: data)
        activeLease = lease
        return lease
    }

    private func wipeLocalSecretsLocked() throws {
        try storage.delete(leaseKey)
        activeLease = nil
        session = nil
        // 时间状态一并清除：重新登录拿到新租约后由 resetBaseline 重建
        let timeKey = guardian.storageKey
        try? storage.delete(timeKey)
    }
}

/// 离线剩余状态的只读快照。
public struct OfflineStatus: Sendable, Equatable {
    public let expiresAt: Date
    public let secondsUntilExpiry: Double
    public let monotonicBudget: Double
    public let monotonicUsed: Double
    public let monotonicRemaining: Double
    public let epoch: Int
    public let revoked: Bool
}

private extension Optional {
    func unwrapOrThrow(_ error: AccessControlError) throws -> Wrapped {
        guard let value = self else { throw error }
        return value
    }
}
