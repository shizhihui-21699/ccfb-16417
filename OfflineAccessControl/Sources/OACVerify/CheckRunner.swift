import Foundation

/// 极简断言框架（当前环境无 XCTest，用可执行程序承载全部场景验证）。
/// 每个用例独立运行，失败仅记录不中断，最终汇总退出码：全部通过 exit(0)，否则 exit(1)。
final class CheckRunner: @unchecked Sendable {
    private(set) var passed = 0
    private(set) var failed = 0
    private var failures: [String] = []
    private var currentCase = ""

    func run(_ name: String, _ body: () throws -> Void) {
        currentCase = name
        do {
            try body()
            passed += 1
            print("  ✓ \(name)")
        } catch {
            failed += 1
            failures.append("\(name): \(error)")
            print("  ✗ \(name) — \(error)")
        }
    }

    func expectEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String = "") throws {
        if actual != expected {
            throw fail("expected \(expected), got \(actual) \(message)")
        }
    }

    func expectTrue(_ condition: Bool, _ message: String = "") throws {
        if !condition { throw fail("expected true \(message)") }
    }

    func expectNoThrow(_ body: @autoclosure () throws -> Void, _ message: String = "") {
        do {
            try body()
        } catch {
            // 记录为用例失败：通过抛 CheckFailure 交给 run 捕获
            // 这里无法直接 throw（签名非 throws），改用计数
            failed += 1
            failures.append("[\(currentCase)] unexpected error: \(error) \(message)")
            print("  ✗ \(currentCase) — unexpected error: \(error)")
        }
    }

    /// 期望表达式抛出指定错误。
    func expectThrows<E: Error & Equatable>(
        _ expected: E,
        _ body: () throws -> Void,
        _ message: String = ""
    ) {
        do {
            try body()
            failed += 1
            let detail = "[\(currentCase)] expected error \(expected) but no error was thrown \(message)"
            failures.append(detail)
            print("  ✗ \(detail)")
        } catch let actual as E {
            if actual != expected {
                failed += 1
                let detail = "[\(currentCase)] expected \(expected), got \(actual) \(message)"
                failures.append(detail)
                print("  ✗ \(detail)")
            }
        } catch {
            failed += 1
            let detail = "[\(currentCase)] expected \(expected), got other error \(error) \(message)"
            failures.append(detail)
            print("  ✗ \(detail)")
        }
    }

    /// 期望表达式抛出任意错误。
    func expectAnyThrow(_ body: () throws -> Void, _ message: String = "") {
        do {
            try body()
            failed += 1
            let detail = "[\(currentCase)] expected an error but none was thrown \(message)"
            failures.append(detail)
            print("  ✗ \(detail)")
        } catch {
            // ok
        }
    }

    private func fail(_ detail: String) -> CheckFailure {
        CheckFailure(detail: "[\(currentCase)] \(detail)")
    }

    func summary() -> Int32 {
        print("")
        print("== 结果：\(passed) 通过，\(failed) 失败 ==")
        if !failures.isEmpty {
            print("失败明细：")
            failures.forEach { print("  - \($0)") }
            return 1
        }
        return 0
    }
}

struct CheckFailure: Error {
    let detail: String
    var localizedDescription: String { detail }
}
