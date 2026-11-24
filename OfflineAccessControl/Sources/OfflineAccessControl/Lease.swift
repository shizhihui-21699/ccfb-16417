import Foundation
import CryptoKit

/// 离线租约载荷：服务器对「某用户在某设备上，在限定条件内可离线访问数据」的签名授权。
///
/// 离线期间客户端的全部安全判定都只依赖这张票据 + 本地时钟状态，不发起任何网络请求，
/// 因此工地连续断网多天也能工作——只要票据本身还在有效期与额度内。
public struct LeasePayload: Codable, Sendable, Equatable {
    /// 租约版本号，每次服务器签发递增；客户端只接受比当前更新的租约（防重放旧租约）
    public let leaseVersion: Int
    public let userId: String
    public let deviceId: String
    /// 密钥轮换纪元。换 epoch 后旧租约解不开新 epoch 的文件（前向保密，见 OfflineAccessManager）
    public let epoch: Int
    /// 绝对到期时刻（墙钟）。建议 7~14 天，按「最长可接受的失陷暴露窗口」设定
    public let expiresAt: Date
    /// 单调时钟累计使用额度（秒）。即使墙钟被冻结，App 累计使用时长超额度也会锁
    public let monotonicBudgetSeconds: Double
    /// 签发时刻（墙钟）
    public let issuedAt: Date
    /// ECIES 信封：只有本设备的 SE 私钥能解出其中的 KEK
    public let wrappedKEK: ECIESEnvelope
}

/// 带签名的租约信封。签名只覆盖规范化（键排序）后的载荷编码。
public struct OfflineLease: Codable, Sendable, Equatable {
    public let payload: LeasePayload
    /// 服务器 P-256 签名密钥对 payload 的 ECDSA 签名（rawRepresentation）
    public let signature: Data
}

/// 租约签发方抽象。生产实现位于服务端（密钥在 HSM/KMS 里），App 内只内置验签公钥。
public protocol LeaseAuthority: Sendable {
    func verify(lease: OfflineLease) throws
}

/// 服务器侧签名器（测试 / demo 使用；生产环境此密钥永不下发到客户端）。
public final class LeaseSigner: LeaseAuthority, @unchecked Sendable {
    private let privateKey: P256.Signing.PrivateKey
    private let lock = NSLock()

    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKeyRaw: Data { privateKey.publicKey.rawRepresentation }

    public func sign(_ payload: LeasePayload) throws -> OfflineLease {
        let body = try LeaseCanonical.encode(payload)
        let signature = try privateKey.signature(for: body).rawRepresentation
        return OfflineLease(payload: payload, signature: signature)
    }

    public func verify(lease: OfflineLease) throws {
        try LeaseCanonical.verify(lease, publicKeyRaw: publicKeyRaw)
    }

    /// 通用签名：吊销名单等其他服务器签名产物复用同一把签名密钥。
    public func sign(body: Data) throws -> Data {
        try privateKey.signature(for: body).rawRepresentation
    }
}

/// 客户端内置的验签器：只持有服务器公钥，无法伪造租约。
public struct LeaseVerifier: LeaseAuthority {
    private let publicKey: P256.Signing.PublicKey

    public init(publicKeyRaw: Data) throws {
        self.publicKey = try P256.Signing.PublicKey(rawRepresentation: publicKeyRaw)
    }

    public func verify(lease: OfflineLease) throws {
        try LeaseCanonical.verify(lease, publicKey: publicKey)
    }

    /// 通用验签：吊销名单等其他服务器签名产物复用同一信任锚。
    public func verifySignature(_ rawSignature: Data, for body: Data) throws -> Bool {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: rawSignature)
        return publicKey.isValidSignature(signature, for: body)
    }
}

enum LeaseCanonical {
    /// 规范化编码：固定 ISO8601 日期策略 + 键排序，保证签名/验签两端字节一致。
    static func encode(_ payload: LeasePayload) throws -> Data {
        try JSONEncoder.iso8601.encode(payload)
    }

    static func verify(_ lease: OfflineLease, publicKeyRaw: Data) throws {
        let key = try P256.Signing.PublicKey(rawRepresentation: publicKeyRaw)
        try verify(lease, publicKey: key)
    }

    static func verify(_ lease: OfflineLease, publicKey: P256.Signing.PublicKey) throws {
        let body = try encode(lease.payload)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: lease.signature)
        guard publicKey.isValidSignature(signature, for: body) else {
            throw AccessControlError.leaseSignatureInvalid
        }
    }
}
