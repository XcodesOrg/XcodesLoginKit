import Foundation

/// Imports fastlane/Spaceship cookie data into a URL session.
///
/// Use this when a user already has a fastlane session and you want ``Client`` to reuse those cookies
/// instead of asking the user to sign in again.
public final class FastlaneSessionImporter: Sendable {
    /// Errors raised while importing cookies into a session.
    public enum Error: Swift.Error, Equatable, Sendable {
        /// The target session does not have an `HTTPCookieStorage`.
        case missingCookieStorage
    }

    private let parser: FastlaneCookieParser

    /// Creates an importer with the parser used to decode fastlane cookie files.
    public init(parser: FastlaneCookieParser = FastlaneCookieParser()) {
        self.parser = parser
    }

    /// Parses fastlane cookie content and stores the resulting cookies in a URL session.
    /// - Parameters:
    ///   - cookieString: The raw fastlane cookie file or `FASTLANE_SESSION` value.
    ///   - session: The session whose cookie storage should receive the parsed cookies.
    /// - Returns: The cookies that were imported.
    @discardableResult
    public func importCookies(cookieString: String, into session: URLSession) throws -> [HTTPCookie] {
        guard let cookieStorage = session.configuration.httpCookieStorage else {
            throw Error.missingCookieStorage
        }

        let cookies = try parser.parse(cookieString: cookieString)
        cookies.forEach(cookieStorage.setCookie)
        return cookies
    }

    /// Reads fastlane cookie content from disk and stores the resulting cookies in a URL session.
    /// - Parameters:
    ///   - fileURL: The cookie file URL, usually under `~/.fastlane/spaceship/<apple-id>/cookie`.
    ///   - session: The session whose cookie storage should receive the parsed cookies.
    /// - Returns: The cookies that were imported.
    @discardableResult
    public func importCookies(from fileURL: URL, into session: URLSession) throws -> [HTTPCookie] {
        let cookieString = try String(contentsOf: fileURL)
        return try importCookies(cookieString: cookieString, into: session)
    }
}
