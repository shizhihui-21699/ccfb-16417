import Foundation

/// 离线访问控制参考实现——端到端场景验证入口。
/// 运行：swift run oac-verify
@main
struct Main {
    static func main() {
        let runner = CheckRunner()
        print("── 时间与租约场景 ──")
        TimeAndLeaseScenarios.register(in: runner)
        print("── 吊销与密码学场景 ──")
        RevocationAndCryptoScenarios.register(in: runner)
        let code = runner.summary()
        exit(code)
    }
}
