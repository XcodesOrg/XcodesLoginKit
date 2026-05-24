import XCTest
import os
@testable import XcodesLoginKit

final class XcodesLoginKitTests: XCTestCase {
    private var fastlaneCookieFileURL: URL {
        Bundle.module.url(forResource: "FastlaneCookies", withExtension: "yml", subdirectory: "Fixtures")!
    }

    func testFastlaneCookieParserParsesCookies() throws {
        let cookieString = try String(contentsOf: fastlaneCookieFileURL)

        let parser = FastlaneCookieParser()
        let cookies = try parser.parse(cookieString: cookieString)

        XCTAssertEqual(cookies.count, 3)

        XCTAssertEqual(cookies[0].name, "myacinfo")
        XCTAssertEqual(cookies[0].value, "myacinfo_dummy")
        XCTAssertEqual(cookies[0].domain, ".apple.com")
        XCTAssertEqual(cookies[0].path, "/")
        XCTAssertEqual(cookies[0].isSecure, true)

        XCTAssertEqual(cookies[1].name, "DES5a8153bb0fcd039d87286b59d3accea2")
        XCTAssertEqual(cookies[1].value, "DES5a8153bb0fcd039d87286b59d3accea2_dummy")
        XCTAssertEqual(cookies[1].domain, ".idmsa.apple.com")
        XCTAssertEqual(cookies[1].path, "/")
        XCTAssertEqual(cookies[1].isSecure, true)

        XCTAssertEqual(cookies[2].name, "dqsid")
        XCTAssertEqual(cookies[2].value, "dqsid_dummy")
        XCTAssertEqual(cookies[2].domain, "appstoreconnect.apple.com")
        XCTAssertEqual(cookies[2].path, "/")
        XCTAssertEqual(cookies[2].isSecure, true)
    }

    func testFastlaneSessionImporterImportsCookieStringIntoSession() throws {
        let cookieString = try String(contentsOf: fastlaneCookieFileURL)
        let session = URLSession(configuration: .ephemeral)

        let cookies = try FastlaneSessionImporter().importCookies(cookieString: cookieString, into: session)

        XCTAssertEqual(cookies.count, 3)
        XCTAssertEqual(session.configuration.httpCookieStorage?.cookies?.count, 3)
        XCTAssertEqual(session.configuration.httpCookieStorage?.cookies?.map(\.name).sorted(), [
            "DES5a8153bb0fcd039d87286b59d3accea2",
            "dqsid",
            "myacinfo"
        ])
    }

    func testFastlaneSessionImporterImportsCookieFileIntoSession() throws {
        let session = URLSession(configuration: .ephemeral)

        let cookies = try FastlaneSessionImporter().importCookies(from: fastlaneCookieFileURL, into: session)

        XCTAssertEqual(cookies.count, 3)
        XCTAssertEqual(session.configuration.httpCookieStorage?.cookies?.contains(cookies[0]), true)
    }

    func testFastlaneSessionLoaderCreatesSessionFromEnvironmentCookieString() throws {
        let cookieString = try String(contentsOf: fastlaneCookieFileURL)

        let session = try FastlaneSessionLoader().session(
            fastlaneUser: FastlaneSessionLoader.Constants.fastlaneSessionEnvVarName,
            environmentValue: { key in
                key == FastlaneSessionLoader.Constants.fastlaneSessionEnvVarName ? cookieString : nil
            }
        )

        XCTAssertEqual(session.configuration.httpCookieStorage?.cookies?.count, 3)
    }

    func testFastlaneSessionLoaderThrowsWhenEnvironmentCookieIsMissing() {
        XCTAssertThrowsError(
            try FastlaneSessionLoader().session(
                fastlaneUser: FastlaneSessionLoader.Constants.fastlaneSessionEnvVarName,
                environmentValue: { _ in nil }
            )
        ) { error in
            XCTAssertEqual(
                error as? FastlaneSessionLoader.Error,
                .missingEnvironmentVariable(FastlaneSessionLoader.Constants.fastlaneSessionEnvVarName)
            )
        }
    }

    func testDeveloperPortalSessionServiceValidatesADCSessionRequest() async throws {
        let recorder = URLRecorder()
        let service = DeveloperPortalSessionService(
            loadData: { request in
                if let url = request.url {
                    recorder.record(url)
                }

                let response = try XCTUnwrap(HTTPURLResponse(
                    url: try XCTUnwrap(request.url),
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                ))
                return (Data(), response)
            }
        )

        try await service.validateADCSession(path: "/download/more")

        let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(recorder.url), resolvingAgainstBaseURL: false))
        XCTAssertEqual(components.path, "/services/download")
        XCTAssertEqual(components.queryItems?.first(where: { $0.name == "path" })?.value, "/download/more")
    }

    func testDeveloperPortalSessionServiceMapsUnauthorizedStatus() async throws {
        enum UnauthorizedTestError: Error, Equatable {
            case notAuthorized
        }

        let service = DeveloperPortalSessionService(
            loadData: { request in
                let response = try XCTUnwrap(HTTPURLResponse(
                    url: try XCTUnwrap(request.url),
                    statusCode: 401,
                    httpVersion: nil,
                    headerFields: nil
                ))
                return (Data(), response)
            },
            unauthorizedError: { UnauthorizedTestError.notAuthorized }
        )

        do {
            try await service.validateADCSession(path: "/download/more")
            XCTFail("Expected unauthorized validation to throw")
        } catch let error as UnauthorizedTestError {
            XCTAssertEqual(error, .notAuthorized)
        }
    }

    func testAppleSessionServiceLogoutClearsSessionAndDefaultUsername() async throws {
        let recorder = AppleSessionRecorder(defaultUsername: "test@example.com")
        let service = AppleSessionService(dependencies: recorder.dependencies())

        try await service.logout()

        XCTAssertEqual(recorder.didSignout, true)
        XCTAssertEqual(recorder.removedKey, "test@example.com")
        XCTAssertNil(recorder.defaultUsername)
    }

    func testAppleSessionServiceLoginRemovesStoredPasswordAfterInvalidCredentials() async throws {
        let recorder = AppleSessionRecorder(defaultUsername: "test@example.com")
        recorder.loginOutcome = .invalidCredentials(username: "test@example.com")
        let service = AppleSessionService(dependencies: recorder.dependencies())

        do {
            try await service.login("test@example.com", password: "bad-password")
            XCTFail("Expected invalid credentials to throw")
        } catch AuthenticationError.invalidUsernameOrPassword {
            XCTAssertEqual(recorder.removedKey, "test@example.com")
        }
    }
}

private final class URLRecorder: Sendable {
    private let storedURL = OSAllocatedUnfairLock<URL?>(initialState: nil)

    var url: URL? {
        storedURL.withLock { $0 }
    }

    func record(_ url: URL) {
        storedURL.withLock { $0 = url }
    }
}

private final class AppleSessionRecorder: Sendable {
    enum LoginOutcome: Sendable {
        case success
        case invalidCredentials(username: String)
    }

    private struct State: Sendable {
        var defaultUsername: String?
        var didSignout = false
        var removedKey: String?
        var loginOutcome: LoginOutcome = .success
    }

    private let state: OSAllocatedUnfairLock<State>

    init(defaultUsername: String?) {
        self.state = OSAllocatedUnfairLock(initialState: State(defaultUsername: defaultUsername))
    }

    var defaultUsername: String? {
        state.withLock { $0.defaultUsername }
    }

    var didSignout: Bool {
        state.withLock { $0.didSignout }
    }

    var removedKey: String? {
        state.withLock { $0.removedKey }
    }

    var loginOutcome: LoginOutcome {
        get {
            state.withLock { $0.loginOutcome }
        }
        set {
            state.withLock { $0.loginOutcome = newValue }
        }
    }

    func dependencies() -> AppleSessionService.Dependencies {
        AppleSessionService.Dependencies(
            environmentValue: { _ in nil },
            defaultUsername: { self.defaultUsername },
            setDefaultUsername: { username in
                self.state.withLock { $0.defaultUsername = username }
            },
            keychainString: { _ in nil },
            keychainSet: { _, _ in },
            keychainRemove: { key in
                self.state.withLock { $0.removedKey = key }
            },
            readLine: { _ in nil },
            readSecureLine: { _ in nil },
            validateSession: { throw AuthenticationError.invalidSession },
            login: { _, _ in
                switch self.loginOutcome {
                case .success:
                    return
                case .invalidCredentials(let username):
                    throw AuthenticationError.invalidUsernameOrPassword(username: username)
                }
            },
            signout: {
                self.state.withLock { $0.didSignout = true }
            },
            loadData: { request in
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (Data(), response)
            }
        )
    }
}
