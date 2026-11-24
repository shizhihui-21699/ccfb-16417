import Foundation

/// 持久化的时钟状态（存 Keychain，普通 App 沙盒内无法篡改）。
///
/// 单调时间采用「已完成开机周期累计 + 当前开机周期耗时」的幂等记账模型，
/// 避免重启时把同一开机周期的时间重复入账：
/// - `elapsedCompletedBoots`：所有**已结束**开机周期的单调时长之和，
///   仅在检测到 bootId 变化时入账一次；
/// - `currentBootBaseMonotonic`：当前开机周期首次被观测时的单调时钟读数，
///   当前周期耗时 = 当前单调读数 − 该基线；
/// - `lastMonotonic`：上次检查点的单调读数，用于检测同周期内的负跳变（hook 时钟）；
/// - `lastWallTime`：墙钟高水位线，回拨到比它还早即判定篡改。
struct TimeState: Codable, Equatable {
    var lastWallTime: Date
    var lastBootId: String
    var currentBootBaseMonotonic: Double
    var lastMonotonic: Double
    var elapsedCompletedBoots: Double

    /// 总累计单调耗时（秒）。
    func totalMonotonicUsed(nowMonotonic: Double) -> Double {
        elapsedCompletedBoots + max(0, nowMonotonic - currentBootBaseMonotonic)
    }
}

/// 时间守卫：离线有效期判定的唯一入口。
///
/// 威胁与对策对照：
/// 1. 用户手动把系统时间往回调 → 墙钟高水位线检测（`clockTamperingDetected`）；
/// 2. 用户冻结时间/断网后锁死自动校时 → 单调时钟照常走，累计额度耗尽即锁；
/// 3. 关机几天再开机（单调时钟归零，看不见关机时长）→ bootId 变化识别重启，
///    结合墙钟高水位线：关机期间墙钟只要正常流逝就会触发绝对到期；
///    若同时回拨墙钟伪装「只过了一会儿」，则撞高水位线；
/// 4. 单调时钟读数异常回退（越狱 hook）→ 直接判篡改。
///
/// 注意诚实的残余风险（README 详述）：关机 + 越狱后同时伪造墙钟与 bootId 的攻击者，
/// 理论上可以让时间线停摆——此时防护降级为「生物识别 + SE 私钥 + 短租约 TTL」，
/// 暴露窗口被限制在最后一张租约的有效期内，而不是无限期。
public struct TimeGuardian {
    private let storage: SecureStorage
    let storageKey: String
    private let clock: ClockSource
    /// 允许的墙钟抖动（不同时钟源/校时的正常误差），默认 5 分钟
    private let allowedSkew: TimeInterval

    public init(
        storage: SecureStorage,
        clock: ClockSource = SystemClockSource(),
        storageKey: String = "oac.time-state.v1",
        allowedSkew: TimeInterval = 300
    ) {
        self.storage = storage
        self.clock = clock
        self.storageKey = storageKey
        self.allowedSkew = allowedSkew
    }

    /// 只读评估：每次打开敏感文件前调用，不更新状态。
    @discardableResult
    func evaluate(against payload: LeasePayload) throws -> TimeState {
        try runChecks(against: payload, shouldPersist: false)
    }

    /// 检查点：解锁成功、App 进入后台、场景切换时调用，校验通过后把新水位落盘。
    @discardableResult
    func checkpoint(against payload: LeasePayload) throws -> TimeState {
        try runChecks(against: payload, shouldPersist: true)
    }

    /// 拿到新租约（重新联网授权）后重置基线。只接受 leaseVersion 更大的租约，
    /// 版本比较由 OfflineAccessManager 负责；这里只重建时间基线。
    func resetBaseline(using payload: LeasePayload) throws {
        let nowMono = clock.monotonicSeconds()
        let state = TimeState(
            lastWallTime: max(clock.wallTime(), payload.issuedAt),
            lastBootId: clock.bootIdentifier(),
            currentBootBaseMonotonic: nowMono,
            lastMonotonic: nowMono,
            elapsedCompletedBoots: 0
        )
        try persist(state)
    }

    /// 当前累计已用单调时间（秒），用于 UI 展示「离线剩余额度」。
    func monotonicUsed() throws -> Double {
        guard let state = try loadState() else { return 0 }
        return state.totalMonotonicUsed(nowMonotonic: clock.monotonicSeconds())
    }

    // MARK: - internals

    private func runChecks(against payload: LeasePayload, shouldPersist: Bool) throws -> TimeState {
        try validatePayload(payload)

        let nowWall = clock.wallTime()
        let nowMono = clock.monotonicSeconds()
        let nowBoot = clock.bootIdentifier()

        guard var state = try loadState() else {
            // 首次使用：以租约签发时间为水位基线，防止拿到租约后立刻回拨到签发前
            let seeded = TimeState(
                lastWallTime: max(nowWall, payload.issuedAt),
                lastBootId: nowBoot,
                currentBootBaseMonotonic: nowMono,
                lastMonotonic: nowMono,
                elapsedCompletedBoots: 0
            )
            if shouldPersist { try persist(seeded) }
            try checkExpiry(payload: payload, wall: nowWall)
            return seeded
        }

        // 1) 单调时间线对账（含重启识别）
        if state.lastBootId != nowBoot {
            // 检测到重启：把刚结束的开机周期耗时一次性入账（幂等：每个 bootId 只入一次）
            let finishedBootElapsed = max(0, state.lastMonotonic - state.currentBootBaseMonotonic)
            state.elapsedCompletedBoots += finishedBootElapsed
            state.currentBootBaseMonotonic = nowMono
            state.lastMonotonic = nowMono
            state.lastBootId = nowBoot
        } else {
            // 同一次开机内单调时钟只许前进；负跳变说明时钟被 hook
            if nowMono - state.lastMonotonic < -0.001 {
                throw AccessControlError.clockTamperingDetected
            }
            state.lastMonotonic = nowMono
        }

        let totalUsed = state.totalMonotonicUsed(nowMonotonic: nowMono)
        if totalUsed > payload.monotonicBudgetSeconds {
            if shouldPersist { try persist(state) }
            throw AccessControlError.offlineBudgetExhausted
        }

        // 2) 墙钟回拨检测（高水位线，容忍正常抖动）
        if nowWall.addingTimeInterval(allowedSkew) < state.lastWallTime {
            throw AccessControlError.clockTamperingDetected
        }

        // 3) 绝对到期
        try checkExpiry(payload: payload, wall: nowWall)

        // 4) 推进高水位线并落盘
        if nowWall > state.lastWallTime {
            state.lastWallTime = nowWall
        }
        if shouldPersist { try persist(state) }
        return state
    }

    private func checkExpiry(payload: LeasePayload, wall: Date) throws {
        if wall > payload.expiresAt {
            throw AccessControlError.leaseExpired
        }
    }

    private func validatePayload(_ payload: LeasePayload) throws {
        guard payload.expiresAt > payload.issuedAt,
              payload.monotonicBudgetSeconds >= 0,
              !payload.userId.isEmpty,
              !payload.deviceId.isEmpty else {
            throw AccessControlError.malformedLease
        }
    }

    private func loadState() throws -> TimeState? {
        guard let data = try storage.read(storageKey) else { return nil }
        do {
            return try JSONDecoder.iso8601.decode(TimeState.self, from: data)
        } catch {
            throw AccessControlError.decodingFailed
        }
    }

    private func persist(_ state: TimeState) throws {
        try storage.write(
            storageKey,
            data: try JSONEncoder.iso8601.encode(state),
            options: []
        )
    }
}
