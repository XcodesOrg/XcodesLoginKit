/// Supplies the public Apple widget key used by Apple ID authentication requests.
///
/// Apple does not publish a stable endpoint for discovering this value. XcodesLoginKit tries its
/// bundled App Store Connect key first, then a key supplied by this provider, and finally attempts
/// to discover the latest key from Apple's Developer Portal sign-in page.
public struct AppleServiceKeyProvider: Sendable {
    public typealias Loader = @Sendable () async throws -> String

    private let load: Loader

    /// Creates a provider backed by an asynchronous loader.
    public init(load: @escaping Loader) {
        self.load = load
    }

    /// Loads the service key.
    public func serviceKey() async throws -> String {
        try await load()
    }

    /// Returns a provider that always supplies the given service key.
    public static func fixed(_ serviceKey: String) -> Self {
        Self { serviceKey }
    }

    /// The public widget key bundled with this version of XcodesLoginKit.
    public static let bundledAppStoreConnectServiceKey =
        "e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42"

    /// A provider for the public widget key bundled with this version of XcodesLoginKit.
    public static let appStoreConnect = fixed(bundledAppStoreConnectServiceKey)
}

/// Sources XcodesLoginKit can try when resolving Apple's public sign-in service key.
public enum AppleServiceKeySource: String, Equatable, Sendable {
    /// The key bundled with the installed XcodesLoginKit version.
    case bundled
    /// A key supplied by the application through ``AppleServiceKeyProvider``.
    case supplied
    /// A key discovered from Apple's current Developer Portal sign-in page.
    case developerPortal
}
