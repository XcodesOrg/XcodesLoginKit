import Foundation

/// Builds a URL session populated with fastlane/Spaceship authentication cookies.
///
/// Pass the returned session to ``Client/init(urlSession:)`` to reuse an existing fastlane login.
/// `fastlaneUser` can be an Apple ID with a cookie file under `~/.fastlane/spaceship`, or
/// ``Constants/fastlaneSessionEnvVarName`` to read the `FASTLANE_SESSION` environment value.
public final class FastlaneSessionLoader: Sendable {
    /// Constants used by fastlane session loading.
    public enum Constants {
        /// The environment variable name fastlane uses for a serialized session.
        public static let fastlaneSessionEnvVarName = "FASTLANE_SESSION"
        /// The default fastlane Spaceship directory that contains per-user cookie files.
        public static let fastlaneSpaceshipDir = FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent(".fastlane")
            .appendingPathComponent("spaceship")
    }

    /// Errors raised while loading a fastlane session.
    public enum Error: Swift.Error, Equatable, Sendable {
        /// The requested environment variable was not present.
        case missingEnvironmentVariable(String)
    }

    /// Reads an environment value by name.
    public typealias EnvironmentValue = @Sendable (String) -> String?
    /// Creates the URL session that receives imported cookies.
    public typealias SessionFactory = @Sendable () -> URLSession

    private let importer: FastlaneSessionImporter
    private let makeSession: SessionFactory

    /// Creates a loader.
    /// - Parameters:
    ///   - importer: The cookie importer used to parse fastlane cookie content.
    ///   - makeSession: Factory for the session that receives the imported cookies.
    public init(
        importer: FastlaneSessionImporter = FastlaneSessionImporter(),
        makeSession: @escaping SessionFactory = { URLSession(configuration: .ephemeral) }
    ) {
        self.importer = importer
        self.makeSession = makeSession
    }

    /// Creates a URL session containing cookies for a fastlane user or `FASTLANE_SESSION`.
    /// - Parameters:
    ///   - fastlaneUser: An Apple ID directory name, or `FASTLANE_SESSION` to load from the environment.
    ///   - environmentValue: Closure used to read `FASTLANE_SESSION` when requested.
    /// - Returns: A session populated with the imported cookies.
    public func session(
        fastlaneUser: String,
        environmentValue: EnvironmentValue
    ) throws -> URLSession {
        let session = makeSession()

        switch fastlaneUser {
        case Constants.fastlaneSessionEnvVarName:
            guard let cookieString = environmentValue(Constants.fastlaneSessionEnvVarName) else {
                throw Error.missingEnvironmentVariable(Constants.fastlaneSessionEnvVarName)
            }
            try importer.importCookies(cookieString: cookieString, into: session)
        default:
            let cookieFileURL = Self.cookieFileURL(fastlaneUser: fastlaneUser)
            try importer.importCookies(from: cookieFileURL, into: session)
        }

        return session
    }

    /// Returns the default fastlane cookie file URL for an Apple ID.
    public static func cookieFileURL(fastlaneUser: String) -> URL {
        Constants.fastlaneSpaceshipDir
            .appendingPathComponent(fastlaneUser)
            .appendingPathComponent("cookie")
    }
}
