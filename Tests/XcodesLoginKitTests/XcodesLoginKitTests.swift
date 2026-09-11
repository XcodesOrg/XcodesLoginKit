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

    func testClientCheckIsFederatedReturnsFederatedResponse() async throws {
        let client = Client(urlSession: MockURLProtocol.session { request in
            switch request.url {
            case .federate:
                XCTAssertEqual(
                    request.value(forHTTPHeaderField: "X-Apple-Widget-Key"),
                    "e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42"
                )
                return try Self.fixtureResponse(
                    for: request,
                    resource: "FederateCheck",
                    subdirectory: "Fixtures/Login_Federated_Succeeds"
                )
            default:
                XCTFail("Unexpected request to \(String(describing: request.url))")
                return Self.emptyResponse(for: request, statusCode: 500)
            }
        })

        let response = try await client.checkIsFederated(accountName: "test@company.com")

        XCTAssertTrue(response.federated)
        XCTAssertEqual(response.federatedAuthIntro?.orgName, "Test Corp")
        XCTAssertEqual(response.federatedAuthIntro?.idpName, "Microsoft Entra")
        XCTAssertEqual(response.federatedIdpRequest?.idPUrl, "https://login.microsoftonline.com/test-tenant/oauth2/authorize")
        XCTAssertEqual(response.federatedIdpRequest?.requestParams["login_hint"], "test@company.com")
        XCTAssertNotNil(response.idpURL)
    }

    func testClientCheckIsFederatedReturnsNonFederatedResponse() async throws {
        let steps = StepRecorder()
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                switch request.url {
                case .federate:
                    let serviceKey = try XCTUnwrap(request.value(forHTTPHeaderField: "X-Apple-Widget-Key"))
                    steps.record("request:\(serviceKey)")
                    guard serviceKey == "override-widget-key" else {
                        return Self.emptyResponse(for: request, statusCode: 401)
                    }
                    return try Self.fixtureResponse(
                        for: request,
                        resource: "FederateCheckNonFederated",
                        subdirectory: "Fixtures/Login_Federated_Succeeds"
                    )
                case .developerPortalSignInPage:
                    XCTFail("Should not discover a key after the supplied key succeeds")
                    return Self.emptyResponse(for: request, statusCode: 500)
                default:
                    XCTFail("Unexpected request to \(String(describing: request.url))")
                    return Self.emptyResponse(for: request, statusCode: 500)
                }
            },
            serviceKeyProvider: AppleServiceKeyProvider {
                steps.record("provider")
                return "override-widget-key"
            }
        )

        let response = try await client.checkIsFederated(accountName: "test@example.com")

        XCTAssertFalse(response.federated)
        XCTAssertNil(response.federatedIdpRequest)
        XCTAssertNil(response.federatedAuthIntro)
        XCTAssertNil(response.idpURL)
        XCTAssertEqual(steps.values, [
            "request:\(AppleServiceKeyProvider.bundledAppStoreConnectServiceKey)",
            "provider",
            "request:override-widget-key"
        ])
    }

    func testClientDiscoversLatestServiceKeyWhenBundledKeyFailsAndNoKeyIsSupplied() async throws {
        let steps = StepRecorder()
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                switch request.url {
                case .federate:
                    let serviceKey = try XCTUnwrap(request.value(forHTTPHeaderField: "X-Apple-Widget-Key"))
                    steps.record("request:\(serviceKey)")
                    guard serviceKey == Self.signInPageWidgetKey else {
                        return Self.emptyResponse(for: request, statusCode: 401)
                    }
                    return try Self.fixtureResponse(
                        for: request,
                        resource: "FederateCheckNonFederated",
                        subdirectory: "Fixtures/Login_Federated_Succeeds"
                    )
                case .developerPortalSignInPage:
                    steps.record("discover")
                    return try Self.signInPageResponse(for: request)
                default:
                    XCTFail("Unexpected request to \(String(describing: request.url))")
                    return Self.emptyResponse(for: request, statusCode: 500)
                }
            }
        )

        let response = try await client.checkIsFederated(accountName: "test@example.com")

        XCTAssertFalse(response.federated)
        XCTAssertEqual(steps.values, [
            "request:\(AppleServiceKeyProvider.bundledAppStoreConnectServiceKey)",
            "discover",
            "request:\(Self.signInPageWidgetKey)"
        ])
    }

    func testClientDiscoversLatestServiceKeyAfterSuppliedKeyFails() async throws {
        let steps = StepRecorder()
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                switch request.url {
                case .federate:
                    let serviceKey = try XCTUnwrap(request.value(forHTTPHeaderField: "X-Apple-Widget-Key"))
                    steps.record("request:\(serviceKey)")
                    guard serviceKey == Self.signInPageWidgetKey else {
                        return Self.emptyResponse(for: request, statusCode: 401)
                    }
                    return try Self.fixtureResponse(
                        for: request,
                        resource: "FederateCheckNonFederated",
                        subdirectory: "Fixtures/Login_Federated_Succeeds"
                    )
                case .developerPortalSignInPage:
                    steps.record("discover")
                    return try Self.signInPageResponse(for: request)
                default:
                    XCTFail("Unexpected request to \(String(describing: request.url))")
                    return Self.emptyResponse(for: request, statusCode: 500)
                }
            },
            serviceKeyProvider: AppleServiceKeyProvider {
                steps.record("provider")
                return "stale-supplied-key"
            }
        )

        let response = try await client.checkIsFederated(accountName: "test@example.com")

        XCTAssertFalse(response.federated)
        XCTAssertEqual(steps.values, [
            "request:\(AppleServiceKeyProvider.bundledAppStoreConnectServiceKey)",
            "provider",
            "request:stale-supplied-key",
            "discover",
            "request:\(Self.signInPageWidgetKey)"
        ])
    }

    func testClientReturnsTypedErrorWhenEveryServiceKeySourceFails() async throws {
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                switch request.url {
                case .federate:
                    return Self.emptyResponse(for: request, statusCode: 401)
                case .developerPortalSignInPage:
                    return try Self.signInPageResponse(for: request)
                default:
                    XCTFail("Unexpected request to \(String(describing: request.url))")
                    return Self.emptyResponse(for: request, statusCode: 500)
                }
            },
            serviceKeyProvider: .fixed("stale-supplied-key")
        )

        do {
            _ = try await client.checkIsFederated(accountName: "test@example.com")
            XCTFail("Expected service-key resolution to fail")
        } catch AuthenticationError.serviceKeyResolutionFailed(let attemptedSources) {
            XCTAssertEqual(attemptedSources, [.bundled, .supplied, .developerPortal])
            let message = AuthenticationError
                .serviceKeyResolutionFailed(attemptedSources: attemptedSources)
                .localizedDescription
            XCTAssertTrue(message.contains("the bundled key"))
            XCTAssertTrue(message.contains("the supplied key"))
            XCTAssertTrue(message.contains("Apple's Developer Portal"))
        }
    }

    func testHashcashRequestIncludesWidgetKey() throws {
        let request = try URLRequest.federate(account: "test@example.com", serviceKey: "test-widget-key")
        let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))

        XCTAssertEqual(components.queryItems?.first(where: { $0.name == "widgetKey" })?.value, "test-widget-key")
    }

    func testAuthenticationStateDoesNotLoadFallbackWhileBundledKeyWorks() async throws {
        let invocationCounter = InvocationCounter()
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                guard request.url == .federate else {
                    XCTFail("Unexpected request to \(String(describing: request.url))")
                    return Self.emptyResponse(for: request, statusCode: 500)
                }
                return try Self.fixtureResponse(
                    for: request,
                    resource: "FederateCheck",
                    subdirectory: "Fixtures/Login_Federated_Succeeds"
                )
            },
            serviceKeyProvider: AppleServiceKeyProvider {
                await invocationCounter.increment()
                return "test-widget-key"
            }
        )

        let state = try await client.authenticationState(accountName: "test@company.com", password: nil)
        guard case .waitingForFederatedAuthentication = state else {
            return XCTFail("Expected federated authentication")
        }
        let invocationCount = await invocationCounter.value
        XCTAssertEqual(invocationCount, 0)
    }

    func testClientValidateFederatedTokenSucceeds() async throws {
        let client = Client(urlSession: MockURLProtocol.session { request in
            if request.url?.absoluteString.contains("federate/validate") == true {
                return Self.emptyResponse(for: request, statusCode: 200)
            } else if request.url == .olympusSession {
                return try Self.fixtureResponse(
                    for: request,
                    resource: "OlympusSession",
                    subdirectory: "Fixtures/Login_Federated_Succeeds"
                )
            } else {
                XCTFail("Unexpected request to \(String(describing: request.url))")
                return Self.emptyResponse(for: request, statusCode: 500)
            }
        })

        let state = try await client.validateFederatedToken(
            widgetKey: "test-widget-key",
            token: "test-token",
            relayState: "test-relay-state"
        )

        guard case .authenticated(let session) = state else {
            return XCTFail("Expected authenticated state")
        }
        XCTAssertEqual(session.user.fullName, "Test User")
    }

    func testClientValidateFederatedTokenUnexpectedStatusCode() async throws {
        let client = Client(urlSession: MockURLProtocol.session { request in
            if request.url?.absoluteString.contains("federate/validate") == true {
                return Self.emptyResponse(for: request, statusCode: 401)
            } else {
                XCTFail("Unexpected request to \(String(describing: request.url))")
                return Self.emptyResponse(for: request, statusCode: 500)
            }
        })

        do {
            _ = try await client.validateFederatedToken(
                widgetKey: "test-widget-key",
                token: "test-token",
                relayState: "test-relay-state"
            )
            XCTFail("Expected validation to throw")
        } catch AuthenticationError.unexpectedSignInResponse(let statusCode, let message) {
            XCTAssertEqual(statusCode, 401)
            XCTAssertNil(message)
        }
    }

    func testAppleSessionServiceFederatedAccountSkipsPasswordPrompt() async throws {
        let recorder = AppleSessionRecorder(defaultUsername: "test@company.com")
        recorder.federationResponse = FederationResponse(
            federated: true,
            federatedIdpRequest: FederatedIdpRequest(
                idPUrl: "https://login.microsoftonline.com/test-tenant/oauth2/authorize",
                requestParams: ["login_hint": "test@company.com"],
                httpMethod: "GET"
            ),
            federatedAuthIntro: FederatedAuthIntro(
                orgName: "Test Corp",
                idpName: "Microsoft Entra",
                idpUrl: nil,
                orgType: nil,
                accountManagementUrl: nil
            )
        )
        recorder.callbackURLString = "https://idmsa.apple.com/IDMSWebAuth/federate/oidc/callback?widgetKey=test-widget-key&token=test-token&relayState=test-relay-state"
        let service = AppleSessionService(dependencies: recorder.dependencies())

        try await service.loginIfNeeded()

        XCTAssertFalse(recorder.didPromptForPassword)
        XCTAssertEqual(recorder.openedURL?.host, "login.microsoftonline.com")
        XCTAssertTrue(recorder.log.contains { $0.contains("federated authentication") })
        XCTAssertTrue(recorder.didValidateFederatedCallback)
    }

    func testAppleSessionServiceNonFederatedAccountPromptsPassword() async throws {
        let recorder = AppleSessionRecorder(defaultUsername: "test@example.com")
        recorder.password = "password123"
        recorder.federationResponse = FederationResponse(federated: false)
        let service = AppleSessionService(dependencies: recorder.dependencies())

        try await service.loginIfNeeded()

        XCTAssertTrue(recorder.didPromptForPassword)
        XCTAssertNil(recorder.openedURL)
    }
}

private extension XcodesLoginKitTests {
    static let signInPageWidgetKey =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    static func signInPageResponse(for request: URLRequest) throws -> (Data, HTTPURLResponse) {
        let html = #"<html><script>{"widgetKey":"\#(signInPageWidgetKey)"}</script></html>"#
        return (
            Data(html.utf8),
            try XCTUnwrap(HTTPURLResponse(
                url: try XCTUnwrap(request.url),
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/html"]
            ))
        )
    }

    static func fixtureResponse(for request: URLRequest, resource: String, subdirectory: String) throws -> (Data, HTTPURLResponse) {
        let url = try XCTUnwrap(Bundle.module.url(forResource: resource, withExtension: "json", subdirectory: subdirectory))
        let data = try Data(contentsOf: url)
        return (
            data,
            try XCTUnwrap(HTTPURLResponse(
                url: try XCTUnwrap(request.url),
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            ))
        )
    }

    static func emptyResponse(for request: URLRequest, statusCode: Int) -> (Data, HTTPURLResponse) {
        (
            Data(),
            HTTPURLResponse(
                url: request.url!,
                statusCode: statusCode,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
        )
    }
}

private final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    typealias Handler = @Sendable (URLRequest) throws -> (Data, HTTPURLResponse)

    private nonisolated(unsafe) static var handler: Handler?

    static func session(handler: @escaping Handler) -> URLSession {
        self.handler = handler
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        do {
            let (data, response) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
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

private final class StepRecorder: Sendable {
    private let recordedValues = OSAllocatedUnfairLock<[String]>(initialState: [])

    var values: [String] {
        recordedValues.withLock { $0 }
    }

    func record(_ value: String) {
        recordedValues.withLock { $0.append(value) }
    }
}

private actor InvocationCounter {
    private(set) var value = 0

    func increment() {
        value += 1
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
        var didPromptForPassword = false
        var federationResponse = FederationResponse(federated: false)
        var callbackURLString: String?
        var didValidateFederatedCallback = false
        var openedURL: URL?
        var password: String?
        var log: [String] = []
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

    var didPromptForPassword: Bool {
        state.withLock { $0.didPromptForPassword }
    }

    var federationResponse: FederationResponse {
        get {
            state.withLock { $0.federationResponse }
        }
        set {
            state.withLock { $0.federationResponse = newValue }
        }
    }

    var callbackURLString: String? {
        get {
            state.withLock { $0.callbackURLString }
        }
        set {
            state.withLock { $0.callbackURLString = newValue }
        }
    }

    var didValidateFederatedCallback: Bool {
        state.withLock { $0.didValidateFederatedCallback }
    }

    var openedURL: URL? {
        state.withLock { $0.openedURL }
    }

    var password: String? {
        get {
            state.withLock { $0.password }
        }
        set {
            state.withLock { $0.password = newValue }
        }
    }

    var log: [String] {
        state.withLock { $0.log }
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
            readLongLine: { _ in self.state.withLock { $0.callbackURLString } },
            readSecureLine: { _ in
                self.state.withLock {
                    $0.didPromptForPassword = true
                    return $0.password
                }
            },
            validateSession: { throw AuthenticationError.invalidSession },
            login: { _, _ in
                switch self.loginOutcome {
                case .success:
                    return
                case .invalidCredentials(let username):
                    throw AuthenticationError.invalidUsernameOrPassword(username: username)
                }
            },
            checkIsFederated: { _ in self.federationResponse },
            validateFederatedCallbackURL: { _ in
                self.state.withLock { $0.didValidateFederatedCallback = true }
            },
            openURL: { url in
                self.state.withLock { $0.openedURL = url }
            },
            signout: {
                self.state.withLock { $0.didSignout = true }
            },
            loadData: { request in
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (Data(), response)
            },
            log: { message in
                self.state.withLock { $0.log.append(message) }
            }
        )
    }
}
