import Foundation
import Security

/// 基于 Keychain 的敏感存储。
///
/// 关键安全属性：
/// - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`：锁屏后不可读，且不进入 iCloud
///   Keychain / 加密备份，密钥无法随备份迁移到另一台设备；
/// - `kSecAttrAccessControl` + `.biometryAny`（可选 userPresence）：读取必须通过
///   生物识别，且受 Secure Enclave 保护的私钥在配合此属性时系统会强制每操作一验；
/// - access group 可配合 MDM 的 managed app 配置进一步隔离。
public struct KeychainSecureStorage: SecureStorage {
    public let service: String
    public let accessGroup: String?

    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func baseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    public func read(_ key: String) throws -> Data? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess {
            return item as? Data
        }
        if status == errSecItemNotFound {
            return nil
        }
        throw AccessControlError.storageFailure(status)
    }

    public func write(_ key: String, data: Data, options: StorageOptions) throws {
        var attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        if options.contains(.userPresence) {
            var error: Unmanaged<CFError>?
            guard let acl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.biometryAny, .privateKeyUsage],
                &error
            ) else {
                let status = error.map { OSStatus(CFErrorGetCode($0.takeRetainedValue())) }
                throw AccessControlError.storageFailure(status)
            }
            attributes[kSecAttrAccessControl as String] = acl
        }

        // 先尝试更新，不存在则新增。
        let updateStatus = SecItemUpdate(baseQuery(for: key) as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound {
            throw AccessControlError.storageFailure(updateStatus)
        }

        var insertQuery = baseQuery(for: key)
        attributes.forEach { insertQuery[$0.key] = $0.value }
        let insertStatus = SecItemAdd(insertQuery as CFDictionary, nil)
        guard insertStatus == errSecSuccess else {
            throw AccessControlError.storageFailure(insertStatus)
        }
    }

    public func delete(_ key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AccessControlError.storageFailure(status)
        }
    }
}
