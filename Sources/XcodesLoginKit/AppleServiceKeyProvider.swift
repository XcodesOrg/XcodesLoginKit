/// Supplies an explicit Apple widget key for Apple ID authentication requests.
///
/// When a provider is present, XcodesLoginKit tries it before consulting its cache or Apple's
/// current App Store Connect key sources. The loader is asynchronous so applications can source
/// the value from their own configuration service.
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
}

/// Sources XcodesLoginKit can use when resolving Apple's public sign-in service key.
public enum AppleServiceKeySource: String, Equatable, Sendable {
    /// A key supplied explicitly by the application.
    case supplied
    /// A key read from XcodesLoginKit's best-effort cache.
    case cache
    /// A key read from App Store Connect's unauthenticated sign-out redirect.
    case appStoreConnectSignOut
    /// A key read from App Store Connect's legacy Olympus configuration endpoint.
    case olympus
}

/// Why an Apple service-key source did not produce a usable key.
public enum AppleServiceKeyFailure: Swift.Error, Equatable, Sendable {
    /// The source could not be reached.
    case network(description: String)
    /// The response was not an HTTP response.
    case invalidResponse
    /// The source returned an HTTP error.
    case httpStatus(code: Int, bodyPreview: String?)
    /// The App Store Connect sign-out response did not contain a redirect.
    case missingRedirect
    /// The sign-out redirect could not be parsed.
    case invalidRedirect
    /// The source returned a response without a service key.
    case missingKey

    /// Whether retrying this failure later may succeed without an application update.
    public var isRetryable: Bool {
        switch self {
        case .network:
            return true
        case let .httpStatus(code, _):
            return code == 429 || code >= 500
        case .invalidResponse, .missingRedirect, .invalidRedirect, .missingKey:
            return false
        }
    }
}

/// A failed attempt to resolve Apple's public sign-in service key.
public struct AppleServiceKeyAttempt: Equatable, Sendable {
    /// The source that was attempted.
    public let source: AppleServiceKeySource
    /// The reason the source did not produce a usable key.
    public let failure: AppleServiceKeyFailure

    public init(source: AppleServiceKeySource, failure: AppleServiceKeyFailure) {
        self.source = source
        self.failure = failure
    }
}
