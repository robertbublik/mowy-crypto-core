// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "MowyProtectedKeyStorage",
    platforms: [
        .macOS(.v15),
        .iOS(.v15),
    ],
    targets: [
        .target(
            name: "MowyProtectedKeyStorage",
            path: ".",
            exclude: ["Tests"],
            sources: ["MowyProtectedKeyStore.swift"]
        ),
        .testTarget(
            name: "MowyProtectedKeyStorageTests",
            dependencies: ["MowyProtectedKeyStorage"],
            path: "Tests"
        ),
    ],
    swiftLanguageModes: [.v5]
)
