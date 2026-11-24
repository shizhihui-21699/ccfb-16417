import Foundation
import CryptoKit

/// ECIES 信封（P-256 ECDH + HKDF + AES-GCM），用于服务器把 KEK 安全投递给特定设备。
///
/// 流程（加密方=服务器）：
/// 1. 生成临时 P-256 密钥对 `ephemeral`；
/// 2. 与设备登记的 ECDH 公钥做 ECDH 得共享秘密；
/// 3. HKDF-SHA256（info 绑定设备 id，防跨设备混用）派生内容加密密钥；
/// 4. AES-GCM 加密 KEK，AAD 绑定上下文标签。
///
/// 只有持有对应私钥（且通过 SE 生物识别）的那台设备能完成第 2 步，从而解密。
/// 备份恢复到别的设备：Keychain 项是 ThisDeviceOnly 不会迁移；即使整份文件被拷走，
/// 没有 SE 内的私钥也解不开。
public struct ECIESEnvelope: Codable, Sendable, Equatable {
    public let ephemeralPublic: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data
}

public enum KeyWrapping {

    /// 用设备 ECDH 公钥包裹任意对称密钥材料（服务器侧 / 测试辅助使用）。
    public static func wrap(
        keyMaterial: Data,
        recipientPublicRaw: Data,
        deviceId: String,
        aad: Data = Data("offline-access-kek-v1".utf8)
    ) throws -> ECIESEnvelope {
        let recipient = try P256.KeyAgreement.PublicKey(rawRepresentation: recipientPublicRaw)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let derived = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.publicKey.rawRepresentation,
            sharedInfo: Data("ecies:\(deviceId)".utf8),
            outputByteCount: 32
        )
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(
            keyMaterial,
            using: derived,
            nonce: nonce,
            authenticating: aad
        )
        return ECIESEnvelope(
            ephemeralPublic: ephemeral.publicKey.rawRepresentation,
            nonce: Data(nonce),
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
    }

    /// 用本机 ECDH 私钥解包。SE 场景下 ECDH 在安全隔区内完成，且会触发生物识别。
    public static func unwrap(
        envelope: ECIESEnvelope,
        identity: DeviceIdentity,
        deviceId: String,
        aad: Data = Data("offline-access-kek-v1".utf8)
    ) throws -> Data {
        let shared = try identity.deriveSharedSecret(peerPublicRaw: envelope.ephemeralPublic)
        let derived = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: envelope.ephemeralPublic,
            sharedInfo: Data("ecies:\(deviceId)".utf8),
            outputByteCount: 32
        )
        let nonce = try AES.GCM.Nonce(data: envelope.nonce)
        let box = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: envelope.ciphertext,
            tag: envelope.tag
        )
        return try AES.GCM.open(box, using: derived, authenticating: aad)
    }
}
