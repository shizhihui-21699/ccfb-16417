// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OfflineAccessControl",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "OfflineAccessControl", targets: ["OfflineAccessControl"]),
        .executable(name: "oac-verify", targets: ["OACVerify"])
    ],
    targets: [
        .target(name: "OfflineAccessControl"),
        .executableTarget(
            name: "OACVerify",
            dependencies: ["OfflineAccessControl"]
        )
    ]
)
