import Foundation

/// 敏感持久化的访问选项。
/// 真实 App 中 Keychain 项应使用设备绑定、不参与 iCloud 备份/同步，
/// 这样恢复到另一台设备时密钥不会随之迁移（设备绑定的关键一环）。
public struct StorageOptions: OptionSet, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// 需要当前用户在场（生物识别 / 设备密码）才能读取。
    public static let userPresence = StorageOptions(rawValue: 1 << 0)
}

/// 敏感数据的安全存储抽象。
/// 生产实现为 Keychain（见 ``KeychainSecureStorage``）；
/// 测试与命令行环境使用进程内存实现，避免触发系统鉴权弹窗。
public protocol SecureStorage: Sendable {
    func read(_ key: String) throws -> Data?
    func write(_ key: String, data: Data, options: StorageOptions) throws
    func delete(_ key: String) throws
}

/// 仅供测试使用的进程内存存储。数据不落盘，进程退出即销毁。
public final class InMemorySecureStorage: SecureStorage, @unchecked Sendable {
    private var box: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func read(_ key: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return box[key]
    }

    public func write(_ key: String, data: Data, options: StorageOptions) throws {
        lock.lock(); defer { lock.unlock() }
        box[key] = data
    }

    public func delete(_ key: String) throws {
        lock.lock(); defer { lock.unlock() }
        box.removeValue(forKey: key)
    }
}
