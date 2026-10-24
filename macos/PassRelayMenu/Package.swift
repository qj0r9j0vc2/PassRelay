// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PassRelayMenu",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "PassRelayMenu",
            path: "Sources/PassRelayMenu",
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("ServiceManagement"),
            ]
        )
    ]
)
