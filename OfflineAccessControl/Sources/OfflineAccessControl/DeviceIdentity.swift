import Foundation
import CryptoKit
import Security

/// 注册凭证：设备首次登录时上送给服务器，服务器校验后把两把公钥与该用户/设备绑定。
/// 私钥永远不出设备（SE 场景下连系统软件都读不出来，只能句柄引用）。
public struct EnrollmentTicket: Codable, Sendable, Equatable {
    public let userId: String
    public let deviceId: String
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data
    public let usesSecureEnclave: Bool
    public let issuedAt: Date
}

/// 持久化的设备身份记录。
///
/// `signingPrivateData` / `keyAgreementPrivateData`：
/// - SE 场景存的是 SecKey 的**引用句柄**（不是私钥本体，本体熔死在安全隔区）；
/// - 降级场景存软件私钥表示，但落盘位置是 `ThisDeviceOnly` Keychain，读取需生物识别。
struct IdentityRecord: Codable {
    let userId: String
    let deviceId: String
    let usesSecureEnclave: Bool
    let signingPrivateData: Data
    let keyAgreementPrivateData: Data
}

/// ECDH 私钥包装。
/// CryptoKit 的 SE/软件私钥是不同具体类型且协议存在体无法直接调用
/// `sharedSecretFromKeyAgreement`（关联类型限制），用枚举在调用点展开。
enum KeyAgreementKey {
    case secureEnclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
    case software(P256.KeyAgreement.PrivateKey)

    var publicKeyRaw: Data {
        switch self {
        case .secureEnclave(let k): return k.publicKey.rawRepresentation
        case .software(let k): return k.publicKey.rawRepresentation
        }
    }

    func sharedSecret(peerPublicRaw: Data) throws -> SharedSecret {
        let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: peerPublicRaw)
        switch self {
        case .secureEnclave(let k):
            return try k.sharedSecretFromKeyAgreement(with: peer)
        case .software(let k):
            return try k.sharedSecretFromKeyAgreement(with: peer)
        }
    }
}

/// ECDSA 签名私钥包装。
enum SigningKey {
    case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)
    case software(P256.Signing.PrivateKey)

    var publicKeyRaw: Data {
        switch self {
        case .secureEnclave(let k): return k.publicKey.rawRepresentation
        case .software(let k): return k.publicKey.rawRepresentation
        }
    }

    func sign(_ data: Data) throws -> Data {
        switch self {
        case .secureEnclave(let k):
            return try k.signature(for: data).rawRepresentation
        case .software(let k):
            return try k.signature(for: data).rawRepresentation
        }
    }
}

/// 设备身份管理器：负责密钥的创建、持久化、加载，以及向服务器证明「我是那台登记过的设备」。
public final class DeviceIdentity: @unchecked Sendable {
    private let storage: SecureStorage
    private let storageKey: String
    /// 可注入的 SE 可用性判断；测试/模拟器环境强制 false 走软件降级，
    /// 避免在无 GUI 的测试进程里触发真实生物识别流程。
    private let secureEnclaveAvailable: @Sendable () -> Bool
    private let stateLock = NSLock()
    private var record: IdentityRecord?
    private var signingKey: SigningKey?
    private var agreementKey: KeyAgreementKey?

    public init(
        storage: SecureStorage,
        storageKey: String = "oac.identity.v1",
        secureEnclaveAvailable: @escaping @Sendable () -> Bool = { SecureEnclave.isAvailable }
    ) {
        self.storage = storage
        self.storageKey = storageKey
        self.secureEnclaveAvailable = secureEnclaveAvailable
    }

    /// 当前设备是否能用 Secure Enclave。模拟器、无 SE 的 Mac 会返回 false，自动走软件降级。
    public var isSecureEnclaveAvailable: Bool {
        secureEnclaveAvailable()
    }

    /// 已登记则加载身份；尚未登记返回 nil。
    @discardableResult
    func load() throws -> IdentityRecord? {
        guard let data = try storage.read(storageKey) else { return nil }
        let decoded = try JSONDecoder.iso8601.decode(IdentityRecord.self, from: data)
        try hydrate(decoded)
        return decoded
    }

    /// 首次登记：生成两把 P-256 密钥并持久化。
    /// 服务器应通过登录流程（密码 + MFA）确认用户身份后才接受注册凭证。
    public func enroll(userId: String, deviceId: String) throws -> EnrollmentTicket {
        let useSE = secureEnclaveAvailable()
        let signing: SigningKey
        let agreement: KeyAgreementKey

        if useSE {
            // biometryAny：每次使用私钥都必须过一次生物识别；
            // 私钥操作在 SE 内完成，系统主核拿不到密钥本体。
            guard let acl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.biometryAny, .privateKeyUsage],
                nil
            ) else {
                throw AccessControlError.storageFailure(nil)
            }
            let s = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl)
            let a = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
            signing = .secureEnclave(s)
            agreement = .secureEnclave(a)
        } else {
            let s = P256.Signing.PrivateKey(compactRepresentable: true)
            let a = P256.KeyAgreement.PrivateKey(compactRepresentable: true)
            signing = .software(s)
            agreement = .software(a)
        }

        let rec = IdentityRecord(
            userId: userId,
            deviceId: deviceId,
            usesSecureEnclave: useSE,
            signingPrivateData: signingData(signing),
            keyAgreementPrivateData: agreementData(agreement)
        )
        try storage.write(
            storageKey,
            data: JSONEncoder.iso8601.encode(rec),
            options: .userPresence
        )
        try hydrate(rec)

        return EnrollmentTicket(
            userId: userId,
            deviceId: deviceId,
            signingPublicKey: signing.publicKeyRaw,
            keyAgreementPublicKey: agreement.publicKeyRaw,
            usesSecureEnclave: useSE,
            issuedAt: Date()
        )
    }

    func currentRecord() -> IdentityRecord? {
        stateLock.lock(); defer { stateLock.unlock() }
        return record
    }

    /// 用设备签名密钥对挑战签名（向服务器做设备 attestation / 刷新租约时使用）。
    public func signChallenge(_ data: Data) throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let key = signingKey else { throw AccessControlError.keyMissing }
        return try key.sign(data)
    }

    public func keyAgreementPublicKey() throws -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let key = agreementKey else { throw AccessControlError.keyMissing }
        return key.publicKeyRaw
    }

    /// 与对端公钥做 ECDH，产出共享秘密（供 ECIES 解包 KEK 使用）。
    func deriveSharedSecret(peerPublicRaw: Data) throws -> SharedSecret {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let key = agreementKey else { throw AccessControlError.keyMissing }
        return try key.sharedSecret(peerPublicRaw: peerPublicRaw)
    }

    // MARK: - internals

    private func hydrate(_ rec: IdentityRecord) throws {
        if rec.usesSecureEnclave {
            let s = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: rec.signingPrivateData)
            let a = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: rec.keyAgreementPrivateData)
            signingKey = .secureEnclave(s)
            agreementKey = .secureEnclave(a)
        } else {
            // 软件密钥用 x963Representation 持久化（SE 密钥才有 dataRepresentation）
            let s = try P256.Signing.PrivateKey(x963Representation: rec.signingPrivateData)
            let a = try P256.KeyAgreement.PrivateKey(x963Representation: rec.keyAgreementPrivateData)
            signingKey = .software(s)
            agreementKey = .software(a)
        }
        record = rec
    }

    private func signingData(_ key: SigningKey) -> Data {
        switch key {
        case .secureEnclave(let k): return k.dataRepresentation
        case .software(let k): return k.x963Representation
        }
    }

    private func agreementData(_ key: KeyAgreementKey) -> Data {
        switch key {
        case .secureEnclave(let k): return k.dataRepresentation
        case .software(let k): return k.x963Representation
        }
    }
}

extension JSONEncoder {
    static let iso8601: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()
}

extension JSONDecoder {
    static let iso8601: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
