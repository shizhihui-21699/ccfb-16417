import Foundation
import CryptoKit
@testable import OfflineAccessControl

/// 验证用的「服务器 + 客户端」装配台：
/// - 软件密钥身份（不触发真实生物识别）
/// - 可控 FakeClock（可拨时间、可模拟重启）
/// - 内存安全存储
/// - 模拟服务器持有租约签名密钥，负责 ECIES 包裹 KEK
final class TestHarness {
    let storage = InMemorySecureStorage()
    let clock: FakeClock
    let identity: DeviceIdentity
    let signer = LeaseSigner()
    let manager: OfflineAccessManager
    let verifier: LeaseVerifier

    let userId = "user-42"
    let deviceId = "device-7"
    let baseDate = Date(timeIntervalSince1970: 1_800_000_000)

    init() throws {
        let clock = FakeClock(startingAt: baseDate)
        self.clock = clock
        identity = DeviceIdentity(storage: storage, secureEnclaveAvailable: { false })
        _ = try identity.enroll(userId: userId, deviceId: deviceId)
        verifier = try LeaseVerifier(publicKeyRaw: signer.publicKeyRaw)
        manager = OfflineAccessManager(
            storage: storage,
            identity: identity,
            verifier: verifier,
            clock: clock
        )
    }

    /// 模拟服务器签发租约。
    func issueLease(
        ttl: TimeInterval = 7 * 24 * 3600,
        budget: Double = 3600,
        epoch: Int = 1,
        leaseVersion: Int = 1,
        kek: SymmetricKey? = nil
    ) throws -> OfflineLease {
        let kek = kek ?? SymmetricKey(size: .bits256)
        let kekData = kek.withUnsafeBytes { Data(Array($0)) }
        let envelope = try KeyWrapping.wrap(
            keyMaterial: kekData,
            recipientPublicRaw: identity.keyAgreementPublicKey(),
            deviceId: deviceId
        )
        let payload = LeasePayload(
            leaseVersion: leaseVersion,
            userId: userId,
            deviceId: deviceId,
            epoch: epoch,
            expiresAt: clock.wallTime().addingTimeInterval(ttl),
            monotonicBudgetSeconds: budget,
            issuedAt: clock.wallTime(),
            wrappedKEK: envelope
        )
        return try signer.sign(payload)
    }

    /// 模拟服务器签发吊销名单。
    func issueRevocation(
        version: Int,
        devices: [String] = [],
        users: [String] = [],
        leaseVersions: [Int] = []
    ) throws -> RevocationList {
        let payload = RevocationPayload(
            version: version,
            revokedDeviceIds: devices,
            revokedUserIds: users,
            revokedLeaseVersions: leaseVersions,
            issuedAt: clock.wallTime()
        )
        let body = try JSONEncoder.iso8601.encode(payload)
        let signature = try signer.sign(body: body)
        return RevocationList(payload: payload, signature: signature)
    }
}

extension SymmetricKey {
    func testData() -> Data {
        withUnsafeBytes { Data(Array($0)) }
    }
}
