// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Demo",
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.89.0"),
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", from: "0.7.0"),
    ],
    targets: [
        .executableTarget(name: "App", dependencies: [.product(name: "Vapor", package: "vapor"), .product(name: "MCP", package: "swift-sdk")]),
    ]
)
