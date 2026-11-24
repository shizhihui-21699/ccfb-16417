import Foundation
import CryptoKit

/// 吊销名单载荷。由服务器签名，版本号单调递增——客户端只接受更新版本，
/// 旧名单无法覆盖新名单（防重放，避免攻击者把一份「还没吊销我」的旧名单塞回来）。
public struct RevocationPayload: Codable, Sendable, Equatable {
    /// 单调递增的名单版本
    public let version: Int
    /// 被吊销的设备 id（离职员工设备、报失手机等）
    public let revokedDeviceIds: [String]
    /// 被吊销的用户 id（整人停用，其名下所有设备一起失效）
    public let revokedUserIds: [String]
    /// 被作废的租约版本（精确吊销某一张已签发租约）
    public let revokedLeaseVersions: [Int]
    public let issuedAt: Date
}

/// 带服务器签名的吊销信封。
public struct RevocationList: Codable, Sendable, Equatable {
    public let payload: RevocationPayload
    public let signature: Data
}

/// 吊销注册表：管理本地名单的验签、版本防重放与查询。
///
/// 关键工程点（回应「吊销指令可能永远送不到」）：
/// - 名单不走推送，而是**拉取模型**：App 在任何一次能联网的时刻（甚至只是借到
///   工友热点、路过有信号的营地）都能从 CDN/对象存储拉一份最新签名名单，几十 KB；
/// - 名单是纯静态签名文件，可挂在任意高可用 CDN 上，不依赖 App 后端在线；
/// - 拉不到就维持上一份名单 + 租约 TTL 兜底，安全性不回退，可用性不受影响。
public final class RevocationRegistry: @unchecked Sendable {
    private let storage: SecureStorage
    private let verifier: LeaseVerifier
    private let storageKey: String
    private let lock = NSLock()

    public init(
        storage: SecureStorage,
        verifier: LeaseVerifier,
        storageKey: String = "oac.revocation.v1"
    ) {
        self.storage = storage
        self.verifier = verifier
        self.storageKey = storageKey
    }

    /// 应用一份从服务端获取的名单。验签失败拒绝，版本倒退拒绝。
    public func apply(_ list: RevocationList) throws {
        let body = try JSONEncoder.iso8601.encode(list.payload)
        let isValid = try verifier.verifySignature(list.signature, for: body)
        guard isValid else {
            throw AccessControlError.leaseSignatureInvalid
        }

        lock.lock()
        let current = try? loadLocked()
        lock.unlock()

        if let current, list.payload.version <= current.payload.version {
            throw AccessControlError.revocationVersionStale
        }
        try storage.write(
            storageKey,
            data: try JSONEncoder.iso8601.encode(list),
            options: []
        )
    }

    /// 当前本地名单版本（无名单返回 0）。
    public func currentVersion() throws -> Int {
        lock.lock(); defer { lock.unlock() }
        return (try? loadLocked())?.payload.version ?? 0
    }

    /// 解锁与每次文件访问前调用：当前租约是否命中吊销。
    public func isRevoked(lease: OfflineLease) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let list = try? loadLocked() else { return false }
        let p = list.payload
        let l = lease.payload
        return p.revokedDeviceIds.contains(l.deviceId)
            || p.revokedUserIds.contains(l.userId)
            || p.revokedLeaseVersions.contains(l.leaseVersion)
    }

    /// 清理本地名单（仅测试 / 用户主动注销时使用）。
    public func purgeLocalList() throws {
        try storage.delete(storageKey)
    }

    // MARK: - internals

    private func loadLocked() throws -> RevocationList? {
        guard let data = try storage.read(storageKey) else { return nil }
        return try JSONDecoder.iso8601.decode(RevocationList.self, from: data)
    }
}
