import Foundation
@testable import OfflineAccessControl

/// 离线工作、租约生命周期、双时钟防回拨场景。
enum TimeAndLeaseScenarios {

    static func register(in runner: CheckRunner) {
        runner.run("正常离线工作：断网 3 天仍可解锁并解密文件") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(ttl: 7 * 24 * 3600, budget: 7 * 24 * 3600))

            h.clock.advance(seconds: 3 * 24 * 3600)
            let session = try h.manager.unlock()

            let sealed = try session.seal(
                fileId: "drawing-A.pdf",
                plaintext: Data("敏感图纸内容".utf8)
            )
            let opened = try session.open(sealed)
            try runner.expectEqual(opened, Data("敏感图纸内容".utf8))
        }

        runner.run("无租约时解锁失败") {
            let h = try TestHarness()
            runner.expectThrows(AccessControlError.leaseMissing) { _ = try h.manager.unlock() }
        }

        runner.run("主动锁定后会话失效、文件访问被拒") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease())
            let session = try h.manager.unlock()
            let sealed = try session.seal(fileId: "f", plaintext: Data("x".utf8))

            h.manager.lock()
            try runner.expectTrue(!h.manager.isUnlocked)
            runner.expectThrows(AccessControlError.sessionLocked) { _ = try session.open(sealed) }
        }

        runner.run("绝对有效期：墙钟超过 TTL 即过期") {
            let h = try TestHarness()
            // 预算给足，确保先撞上墙钟 TTL 而不是单调额度
            try h.manager.installLease(try h.issueLease(ttl: 24 * 3600, budget: 48 * 3600))
            h.clock.advance(seconds: 25 * 3600)
            runner.expectThrows(AccessControlError.leaseExpired) { _ = try h.manager.unlock() }
        }

        runner.run("墙钟回拨 2 小时被判定篡改") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(ttl: 24 * 3600, budget: 3600))
            _ = try h.manager.unlock()

            h.clock.setWallTime(h.clock.wallTime().addingTimeInterval(-2 * 3600))
            runner.expectThrows(AccessControlError.clockTamperingDetected) { _ = try h.manager.unlock() }
        }

        runner.run("小幅时钟抖动（1 分钟）被容忍，不误杀正常用户") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(ttl: 24 * 3600, budget: 3600))
            _ = try h.manager.unlock()

            h.clock.setWallTime(h.clock.wallTime().addingTimeInterval(-60))
            runner.expectNoThrow(_ = try h.manager.unlock())
        }

        runner.run("冻结墙钟也无效：单调额度耗尽即锁") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(ttl: 24 * 3600, budget: 1800))
            _ = try h.manager.unlock()

            h.clock.advance(seconds: 1801)
            runner.expectThrows(AccessControlError.offlineBudgetExhausted) { _ = try h.manager.unlock() }
        }

        runner.run("单调使用量跨检查点累计而非重置") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(ttl: 24 * 3600, budget: 2000))
            _ = try h.manager.unlock()

            h.clock.advance(seconds: 600)
            try h.manager.checkpoint()
            let s1 = try h.manager.offlineStatus(clock: h.clock)
            try runner.expectTrue(s1.monotonicUsed >= 599)

            h.clock.advance(seconds: 600)
            try h.manager.checkpoint()
            let s2 = try h.manager.offlineStatus(clock: h.clock)
            try runner.expectTrue(s2.monotonicUsed >= 1199)
            try runner.expectTrue(abs(s2.monotonicRemaining - 800) <= 2)
        }

        runner.run("重启后单调时间跨开机周期累计，额度仍生效") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(ttl: 48 * 3600, budget: 1000))
            _ = try h.manager.unlock()
            h.clock.advance(seconds: 600)
            try h.manager.checkpoint()

            h.clock.reboot(wallElapsedWhileOff: 10 * 3600)
            _ = try h.manager.unlock() // 重启后首次解锁入账上一周期

            h.clock.advance(seconds: 500)
            runner.expectThrows(AccessControlError.offlineBudgetExhausted) { _ = try h.manager.unlock() }
        }

        runner.run("关机期间回拨墙钟仍被高水位线识破") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(ttl: 48 * 3600, budget: 100_000))
            _ = try h.manager.unlock()
            h.clock.advance(seconds: 3600)
            try h.manager.checkpoint()

            h.clock.reboot(wallElapsedWhileOff: -2 * 3600)
            runner.expectThrows(AccessControlError.clockTamperingDetected) { _ = try h.manager.unlock() }
        }

        runner.run("旧租约重放（更长 TTL、更旧版本）被拒绝") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease(budget: 3600, leaseVersion: 5))

            let stale = try h.issueLease(
                ttl: 365 * 24 * 3600,
                budget: 1_000_000_000,
                epoch: 1,
                leaseVersion: 4
            )
            runner.expectThrows(AccessControlError.revocationVersionStale) {
                try h.manager.installLease(stale)
            }
        }

        runner.run("篡改租约有效期后签名校验失败") {
            let h = try TestHarness()
            let lease = try h.issueLease()
            let altered = LeasePayload(
                leaseVersion: lease.payload.leaseVersion,
                userId: lease.payload.userId,
                deviceId: lease.payload.deviceId,
                epoch: lease.payload.epoch,
                expiresAt: lease.payload.expiresAt.addingTimeInterval(365 * 24 * 3600),
                monotonicBudgetSeconds: lease.payload.monotonicBudgetSeconds,
                issuedAt: lease.payload.issuedAt,
                wrappedKEK: lease.payload.wrappedKEK
            )
            let tampered = OfflineLease(payload: altered, signature: lease.signature)
            runner.expectThrows(AccessControlError.leaseSignatureInvalid) {
                try h.manager.installLease(tampered)
            }
        }
    }
}
