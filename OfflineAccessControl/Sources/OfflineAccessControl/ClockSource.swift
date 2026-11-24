import Foundation
import Darwin

/// 时钟源抽象。
///
/// 设计目的：墙钟（用户可在系统设置里随意改）不可信，不能单独作为离线有效期的
/// 唯一裁判；需要一条用户无法直接修改的单调时间线作为第二条证据，并记录启动次数
/// 以识别「关机一段时间再开机」这种单调时钟天然看不见的时间跨越。
public protocol ClockSource: Sendable {
    /// 墙钟时间（可被用户/NTP 修改，用于绝对到期判定 + 高水位线防回拨）
    func wallTime() -> Date
    /// 单调时间，单位秒。系统重启后归零（用于累计离线使用额度）
    func monotonicSeconds() -> Double
    /// 当前启动周期的标识（每次开机变化，用于检测重启）
    func bootIdentifier() -> String
}

/// 真实设备上的时钟源。
///
/// - 单调时间取 `CLOCK_MONOTONIC_RAW`：不受 settimeofday/NTP 调整影响，
///   且**包含**休眠时长（这一点与 `CLOCK_UPTIME_RAW` 不同——后者休眠不走），
///   工地场景手机长时间放口袋息屏也会计时，无法靠息屏白嫖额度；
/// - 启动标识取 `kern.boottime`，重启后变化；
/// - 两条线都存进 Keychain（不可被普通 App 篡改），由 ``TimeGuardian`` 做交叉校验。
public struct SystemClockSource: ClockSource {
    public init() {}

    public func wallTime() -> Date { Date() }

    public func monotonicSeconds() -> Double {
        var timespec = timespec()
        clock_gettime(CLOCK_MONOTONIC_RAW, &timespec)
        return Double(timespec.tv_sec) + Double(timespec.tv_nsec) / 1_000_000_000.0
    }

    public func bootIdentifier() -> String {
        var mib = [CTL_KERN, KERN_BOOTTIME]
        var bootTime = timeval()
        var size = MemoryLayout<timeval>.size
        let result = sysctl(&mib, UInt32(mib.count), &bootTime, &size, nil, 0)
        if result != 0 {
            // 取不到时退化为单调时钟原值（至少同一次开机内稳定）
            return "mono-\(monotonicSeconds())"
        }
        return "\(bootTime.tv_sec).\(bootTime.tv_usec)"
    }
}

/// 测试用时钟：可自由推进墙钟、单调时钟，可模拟重启。
public final class FakeClock: ClockSource, @unchecked Sendable {
    private var wall: Date
    private var mono: Double
    private var bootId: String
    private let lock = NSLock()
    private var bootSequence = 0

    public init(startingAt wall: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        self.wall = wall
        self.mono = 0
        self.bootSequence = 0
        self.bootId = "boot-0"
    }

    public func wallTime() -> Date {
        lock.lock(); defer { lock.unlock() }
        return wall
    }

    public func monotonicSeconds() -> Double {
        lock.lock(); defer { lock.unlock() }
        return mono
    }

    public func bootIdentifier() -> String {
        lock.lock(); defer { lock.unlock() }
        return bootId
    }

    /// 同时推进墙钟与单调时钟（正常流逝）
    public func advance(seconds: Double) {
        lock.lock(); defer { lock.unlock() }
        wall = wall.addingTimeInterval(seconds)
        mono += seconds
    }

    /// 只拨墙钟（模拟用户手动改时间），单调时钟不动
    public func setWallTime(_ date: Date) {
        lock.lock(); defer { lock.unlock() }
        wall = date
    }

    /// 模拟重启：单调时钟归零、bootId 变化；可附带关机期间流逝的墙钟时间
    public func reboot(wallElapsedWhileOff: Double = 0) {
        lock.lock(); defer { lock.unlock() }
        bootSequence += 1
        bootId = "boot-\(bootSequence)"
        mono = 0
        wall = wall.addingTimeInterval(wallElapsedWhileOff)
    }
}
