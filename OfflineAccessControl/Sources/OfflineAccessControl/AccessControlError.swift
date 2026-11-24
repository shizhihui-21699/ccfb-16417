import Foundation

/// 离线访问控制的全部错误类型。
/// 安全相关错误应原样上报埋点（不要把密钥材料带进日志），便于后台发现篡改尝试。
public enum AccessControlError: Error, Equatable {
    /// 本地不存在有效租约（从未登录或被清理）
    case leaseMissing
    /// 租约签名校验失败，或载荷被篡改
    case leaseSignatureInvalid
    /// 租约已过绝对有效期（墙钟判定）
    case leaseExpired
    /// 单调时钟累计使用额度耗尽
    case offlineBudgetExhausted
    /// 检测到墙钟回拨 / 单调时钟异常回退
    case clockTamperingDetected
    /// 设备或当前租约在吊销名单中
    case deviceRevoked
    /// 吊销名单版本比本地已有的更旧（重放攻击）
    case revocationVersionStale
    /// 找不到所需密钥
    case keyMissing
    /// 租约归属的用户 / 设备与本机身份不匹配
    case identityMismatch
    /// 会话已锁定，需重新走解锁流程
    case sessionLocked
    /// 租约字段自身不合法
    case malformedLease
    /// Keychain / 底层存储错误，附带 OSStatus
    case storageFailure(OSStatus?)
    /// 编解码失败
    case decodingFailed
}
