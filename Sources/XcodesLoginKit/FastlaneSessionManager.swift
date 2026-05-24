import Foundation

public final class FastlaneSessionLoader: Sendable {
    public enum Constants {
        public static let fastlaneSessionEnvVarName = "FASTLANE_SESSION"
        public static let fastlaneSpaceshipDir = FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent(".fastlane")
            .appendingPathComponent("spaceship")
    }

    public enum Error: Swift.Error, Equatable, Sendable {
        case missingEnvironmentVariable(String)
    }

    public typealias EnvironmentValue = @Sendable (String) -> String?
    public typealias SessionFactory = @Sendable () -> URLSession

    private let importer: FastlaneSessionImporter
    private let makeSession: SessionFactory

    public init(
        importer: FastlaneSessionImporter = FastlaneSessionImporter(),
        makeSession: @escaping SessionFactory = { URLSession(configuration: .ephemeral) }
    ) {
        self.importer = importer
        self.makeSession = makeSession
    }

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

    public static func cookieFileURL(fastlaneUser: String) -> URL {
        Constants.fastlaneSpaceshipDir
            .appendingPathComponent(fastlaneUser)
            .appendingPathComponent("cookie")
    }
}
