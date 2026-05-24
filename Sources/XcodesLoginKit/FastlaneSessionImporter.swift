import Foundation

public final class FastlaneSessionImporter: Sendable {
    public enum Error: Swift.Error, Equatable, Sendable {
        case missingCookieStorage
    }

    private let parser: FastlaneCookieParser

    public init(parser: FastlaneCookieParser = FastlaneCookieParser()) {
        self.parser = parser
    }

    @discardableResult
    public func importCookies(cookieString: String, into session: URLSession) throws -> [HTTPCookie] {
        guard let cookieStorage = session.configuration.httpCookieStorage else {
            throw Error.missingCookieStorage
        }

        let cookies = try parser.parse(cookieString: cookieString)
        cookies.forEach(cookieStorage.setCookie)
        return cookies
    }

    @discardableResult
    public func importCookies(from fileURL: URL, into session: URLSession) throws -> [HTTPCookie] {
        let cookieString = try String(contentsOf: fileURL)
        return try importCookies(cookieString: cookieString, into: session)
    }
}
