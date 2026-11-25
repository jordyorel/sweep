// swift-tools-version: 6.0
// SwiftUI front end. Links the Rust static library built by `cargo build --release -p sweep-ffi`.
// Build the .app with `macos/build-app.sh`.
import PackageDescription
import Foundation

let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().path

let package = Package(
    name: "Sweep",
    platforms: [.macOS(.v14)],
    targets: [
        .systemLibrary(name: "CSweep", path: "Sources/CSweep"),
        .executableTarget(
            name: "Sweep",
            dependencies: ["CSweep"],
            linkerSettings: [.unsafeFlags(["-L", "\(repo)/target/release"])]
        ),
    ]
)
