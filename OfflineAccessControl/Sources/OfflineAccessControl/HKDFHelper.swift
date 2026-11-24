import Foundation
import CryptoKit

/// RFC 5869 HKDF（HMAC-SHA256）的最小实现。
///
/// 为什么不用 `SymmetricKey.hkdfDerivedSymmetricKey`：该便捷方法在新版 SDK 中
/// 已从 `SymmetricKey` 上移除（`SharedSecret` 上的同名方法仍保留）。直接基于
/// `HMAC<SHA256>` 实现 extract/expand 两步，在 iOS 13 / macOS 10.15 以上均可用，
/// 行为与 RFC 5869 测试向量一致。
enum HKDFHelper {

    static func deriveKey(
        inputKeyMaterial: SymmetricKey,
        salt: Data,
        info: Data,
        outputByteCount: Int = 32
    ) -> SymmetricKey {
        // ---- Extract：PRK = HMAC(salt, IKM)；salt 为空时用全零 key（RFC 5869 §2.2）----
        let saltKey = SymmetricKey(data: salt)
        let prk = inputKeyMaterial.withUnsafeBytes { ikmBytes -> SymmetricKey in
            let mac = HMAC<SHA256>.authenticationCode(
                for: Data(ikmBytes),
                using: saltKey
            )
            return SymmetricKey(data: Data(mac))
        }

        // ---- Expand：T(1)…T(N) 链式拼接，截断到所需长度 ----
        let n = ceil(Double(outputByteCount) / Double(32))
        var okm = Data()
        var previous = Data()
        for i in 1...Int(n) {
            var input = previous
            input.append(info)
            input.append(UInt8(i))
            let mac = HMAC<SHA256>.authenticationCode(for: input, using: prk)
            previous = Data(mac)
            okm.append(previous)
        }
        okm = Data(okm.prefix(outputByteCount))
        return SymmetricKey(data: okm)
    }
}
