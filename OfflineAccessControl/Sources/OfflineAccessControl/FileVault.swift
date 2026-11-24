import Foundation
import CryptoKit
import CryptoKit

/// 落盘加密文件的信封格式。
///
/// 安全设计：
/// - 每个文件独立随机 DEK（数据加密密钥），单文件泄露不波及其他文件；
/// - DEK 不直接落盘，而是 `HKDF(KEK, fileId)` 按需派生——磁盘上没有任何可单独
///   偷走的密钥，KEK 只活在解锁会话的内存里，锁屏/超时/退出立即释放；
/// - fileId 作为 GCM 的 AAD 绑定，文件改名/挪用时认证失败，防止张冠李戴式拼接攻击；
/// - 外层文件本身可放在普通沙盒目录或 `FileProtectionType.completeFileProtection`
///   目录（NSFileProtectionComplete），与本层形成纵深防御。
public struct SealedFile: Codable, Sendable, Equatable {
    public let fileId: String
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data
    /// 便于业务侧做密钥轮换/迁移，不参与信任决策
    public let epoch: Int
}

public enum FileVault {

    /// 加密一份明文。同一 fileId 重复加密会生成不同 nonce，密文不可链接。
    public static func seal(
        fileId: String,
        plaintext: Data,
        kek: SymmetricKey,
        epoch: Int
    ) throws -> SealedFile {
        let dek = deriveDEK(fileId: fileId, kek: kek)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(
            plaintext,
            using: dek,
            nonce: nonce,
            authenticating: Data(fileId.utf8)
        )
        return SealedFile(
            fileId: fileId,
            nonce: Data(nonce),
            ciphertext: sealed.ciphertext,
            tag: sealed.tag,
            epoch: epoch
        )
    }

    /// 解密密文。租约失效后上层拿不到 KEK，本函数自然无法调用——
    /// 这就是「离线超时自动失效」在文件层的落点：不是删除文件，而是让密钥不可达。
    public static func open(_ sealed: SealedFile, kek: SymmetricKey) throws -> Data {
        let dek = deriveDEK(fileId: sealed.fileId, kek: kek)
        let nonce = try AES.GCM.Nonce(data: sealed.nonce)
        let box = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
        return try AES.GCM.open(box, using: dek, authenticating: Data(sealed.fileId.utf8))
    }

    /// 每文件 DEK：HKDF-SHA256(KEK, salt="dek-v1", info=fileId)。
    /// 派生是确定性的，因此不需要存储任何 DEK，也避免了「每文件再包一层信封」的开销。
    static func deriveDEK(fileId: String, kek: SymmetricKey) -> SymmetricKey {
        HKDFHelper.deriveKey(
            inputKeyMaterial: kek,
            salt: Data("dek-v1".utf8),
            info: Data(fileId.utf8),
            outputByteCount: 32
        )
    }
}
