// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "XcodesLoginKit",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "XcodesLoginKit",
            targets: ["XcodesLoginKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/XcodesOrg/swift-srp", branch: "main"),
        .package(url: "https://github.com/XcodesOrg/AsyncHTTPNetworkService", branch: "main"),
        .package(url: "https://github.com/kinoroy/LibFido2Swift", from: "0.1.4")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "XcodesLoginKit",
            dependencies: [
                .product(name: "SRP", package: "swift-srp"),
                .product(name: "AsyncNetworkService", package: "AsyncHTTPNetworkService"),
                .product(name: "LibFido2Swift", package: "libfido2swift")
            ],
            path: "./Sources")
        ,
        .testTarget(
            name: "XcodesLoginKitTests",
            dependencies: ["XcodesLoginKit"]
        ),
    ]
)
