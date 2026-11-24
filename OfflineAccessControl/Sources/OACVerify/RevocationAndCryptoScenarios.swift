import Foundation
import CryptoKit
@testable import OfflineAccessControl

/// 吊销、密钥轮换、身份绑定、ECIES 绑定场景。
enum RevocationAndCryptoScenarios {

    static func register(in runner: CheckRunner) {

        runner.run("设备吊销：拉到新名单后本地租约自毁") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease())
            _ = try h.manager.unlock()

            let list = try h.issueRevocation(version: 1, devices: [h.deviceId])
            try h.manager.updateRevocationList(list)

            runner.expectThrows(AccessControlError.leaseMissing) { _ = try h.manager.unlock() }
        }

        runner.run("用户吊销：活跃会话的下一次文件操作即被拒") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease())
            let session = try h.manager.unlock()
            let sealed = try session.seal(fileId: "f", plaintext: Data("x".utf8))

            let list = try h.issueRevocation(version: 2, users: [h.userId])
            try h.manager.updateRevocationList(list)

            runner.expectThrows(AccessControlError.sessionLocked) { _ = try session.open(sealed) }
        }

        runner.run("按租约版本精确吊销") {
            let h = try TestHarness()
            _ = try h.issueLease(leaseVersion: 9)
            try h.manager.installLease(try h.issueLease(leaseVersion: 9))

            let list = try h.issueRevocation(version: 1, leaseVersions: [9])
            try h.manager.updateRevocationList(list)
            runner.expectThrows(AccessControlError.leaseMissing) { _ = try h.manager.unlock() }
        }

        runner.run("旧版本吊销名单（重放）被拒绝") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease())

            try h.manager.updateRevocationList(try h.issueRevocation(version: 10))
            try runner.expectTrue(try h.manager.offlineStatus(clock: h.clock).revoked == false)

            runner.expectThrows(AccessControlError.revocationVersionStale) {
                try h.manager.updateRevocationList(try h.issueRevocation(version: 3))
            }
        }

        runner.run("伪造签名的吊销名单被拒绝") {
            let h = try TestHarness()
            let payload = RevocationPayload(
                version: 1,
                revokedDeviceIds: [],
                revokedUserIds: [],
                revokedLeaseVersions: [],
                issuedAt: h.clock.wallTime()
            )
            let attackerKey = P256.Signing.PrivateKey()
            let forgedSig = try attackerKey.signature(
                for: JSONEncoder.iso8601.encode(payload)
            ).rawRepresentation
            let forged = RevocationList(payload: payload, signature: forgedSig)
            runner.expectThrows(AccessControlError.leaseSignatureInvalid) {
                try h.manager.updateRevocationList(forged)
            }
        }

        runner.run("Epoch 轮换：旧密文在新 KEK 下不可读（前向保密）") {
            let h = try TestHarness()
            let oldKEK = SymmetricKey(size: .bits256)
            try h.manager.installLease(
                try h.issueLease(epoch: 1, leaseVersion: 1, kek: oldKEK)
            )
            let v1 = try h.manager.unlock()
            let sealed = try v1.seal(fileId: "blueprint", plaintext: Data("v1密文".utf8))

            let newKEK = SymmetricKey(size: .bits256)
            h.manager.lock()
            try h.manager.installLease(
                try h.issueLease(epoch: 2, leaseVersion: 2, kek: newKEK)
            )
            let v2 = try h.manager.unlock()
            runner.expectAnyThrow { _ = try v2.open(sealed) }
        }

        runner.run("签发给其他设备的租约被身份绑定拒绝") {
            let h = try TestHarness()
            let envelope = try KeyWrapping.wrap(
                keyMaterial: SymmetricKey(size: .bits256).testData(),
                recipientPublicRaw: h.identity.keyAgreementPublicKey(),
                deviceId: "another-device"
            )
            let foreign = LeasePayload(
                leaseVersion: 1,
                userId: h.userId,
                deviceId: "another-device",
                epoch: 1,
                expiresAt: h.clock.wallTime().addingTimeInterval(3600),
                monotonicBudgetSeconds: 3600,
                issuedAt: h.clock.wallTime(),
                wrappedKEK: envelope
            )
            runner.expectThrows(AccessControlError.identityMismatch) {
                try h.manager.installLease(h.signer.sign(foreign))
            }
        }

        runner.run("ECIES：KEK 只有登记设备能解包，AAD 不符即失败") {
            let h = try TestHarness()
            let kekData = SymmetricKey(size: .bits256).testData()
            let envelope = try KeyWrapping.wrap(
                keyMaterial: kekData,
                recipientPublicRaw: h.identity.keyAgreementPublicKey(),
                deviceId: h.deviceId
            )
            let recovered = try KeyWrapping.unwrap(
                envelope: envelope,
                identity: h.identity,
                deviceId: h.deviceId
            )
            try runner.expectEqual(recovered, kekData)

            runner.expectAnyThrow {
                _ = try KeyWrapping.unwrap(
                    envelope: envelope,
                    identity: h.identity,
                    deviceId: h.deviceId,
                    aad: Data("wrong-context".utf8)
                )
            }
        }

        runner.run("文件 fileId 绑定：挪改外壳标识后 GCM 认证失败") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease())
            let session = try h.manager.unlock()
            let sealed = try session.seal(fileId: "doc-A", plaintext: Data("内容".utf8))

            let relabeled = SealedFile(
                fileId: "doc-B",
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
                tag: sealed.tag,
                epoch: sealed.epoch
            )
            runner.expectAnyThrow { _ = try session.open(relabeled) }
        }

        runner.run("每个文件的 DEK 相互独立") {
            let h = try TestHarness()
            try h.manager.installLease(try h.issueLease())
            let session = try h.manager.unlock()
            let dek1 = FileVault.deriveDEK(fileId: "f1", kek: session.kek)
            let dek2 = FileVault.deriveDEK(fileId: "f2", kek: session.kek)
            try runner.expectTrue(dek1.testData() != dek2.testData())
        }
    }
}
