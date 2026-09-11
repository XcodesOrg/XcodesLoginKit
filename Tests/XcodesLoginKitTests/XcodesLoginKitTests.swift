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
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                switch request.url {
                case .federate:
                    XCTAssertEqual(
                        request.value(forHTTPHeaderField: "X-Apple-Widget-Key"),
                        "test-widget-key"
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
            },
            serviceKeyProvider: .fixed("test-widget-key")
        )

        let response = try await client.checkIsFederated(accountName: "test@company.com")

        XCTAssertTrue(response.federated)
        XCTAssertEqual(response.federatedAuthIntro?.orgName, "Test Corp")
        XCTAssertEqual(response.federatedAuthIntro?.idpName, "Microsoft Entra")
        XCTAssertEqual(response.federatedIdpRequest?.idPUrl, "https://login.microsoftonline.com/test-tenant/oauth2/authorize")
        XCTAssertEqual(response.federatedIdpRequest?.requestParams["login_hint"], "test@company.com")
        XCTAssertNotNil(response.idpURL)
    }

    func testClientCheckIsFederatedReturnsNonFederatedResponse() async throws {
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                switch request.url {
                case .federate:
                    let serviceKey = try XCTUnwrap(request.value(forHTTPHeaderField: "X-Apple-Widget-Key"))
                    XCTAssertEqual(serviceKey, "override-widget-key")
                    return try Self.fixtureResponse(
                        for: request,
                        resource: "FederateCheckNonFederated",
                        subdirectory: "Fixtures/Login_Federated_Succeeds"
                    )
                default:
                    XCTFail("Unexpected request to \(String(describing: request.url))")
                    return Self.emptyResponse(for: request, statusCode: 500)
                }
            },
            serviceKeyProvider: .fixed("override-widget-key")
        )

        let response = try await client.checkIsFederated(accountName: "test@example.com")

        XCTAssertFalse(response.federated)
        XCTAssertNil(response.federatedIdpRequest)
        XCTAssertNil(response.federatedAuthIntro)
        XCTAssertNil(response.idpURL)
    }

    func testServiceKeyResolverReadsKeyFromSignOutRedirect() async throws {
        let steps = StepRecorder()
        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: {
                steps.record("signout")
                return Self.signOutResponse(widgetKey: "redirect-widget-key")
            },
            loadOlympusResponse: {
                steps.record("olympus")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        let key = try await resolver.serviceKey()

        XCTAssertEqual(key, "redirect-widget-key")
        XCTAssertEqual(steps.values, ["signout"])
    }

    func testServiceKeyResolverFallsBackToOlympusWhenRedirectHasNoLocation() async throws {
        let steps = StepRecorder()
        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: {
                steps.record("signout")
                return Self.response(url: .appStoreConnectLogout, statusCode: 302)
            },
            loadOlympusResponse: {
                steps.record("olympus")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        let key = try await resolver.serviceKey()

        XCTAssertEqual(key, "olympus-widget-key")
        XCTAssertEqual(steps.values, ["signout", "olympus"])
    }

    func testServiceKeyResolverFallsBackToOlympusWhenSignOutRequestFails() async throws {
        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: {
                throw URLError(.cannotConnectToHost)
            },
            loadOlympusResponse: {
                Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        let key = try await resolver.serviceKey()
        XCTAssertEqual(key, "olympus-widget-key")
    }

    func testServiceKeyResolverFallsBackWhenSuppliedProviderCannotConnect() async throws {
        let steps = StepRecorder()
        let resolver = AppleServiceKeyResolver(
            provider: AppleServiceKeyProvider {
                steps.record("provider")
                throw URLError(.cannotConnectToHost)
            },
            cache: .disabled,
            loadSignOutResponse: {
                steps.record("signout")
                return Self.signOutResponse(widgetKey: "redirect-widget-key")
            },
            loadOlympusResponse: {
                steps.record("olympus")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        let key = try await resolver.serviceKey()

        XCTAssertEqual(key, "redirect-widget-key")
        XCTAssertEqual(steps.values, ["provider", "signout"])
    }

    func testServiceKeyResolverReturnsDetailedFailureForSignOutAndOlympus() async throws {
        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: {
                Self.response(url: .appStoreConnectLogout, statusCode: 302)
            },
            loadOlympusResponse: {
                Self.response(
                    url: URLRequest.olympusServiceKeyFallback.url!,
                    statusCode: 404,
                    body: Data("Not Found".utf8)
                )
            }
        )

        do {
            _ = try await resolver.serviceKey()
            XCTFail("Expected service-key resolution to fail")
        } catch AuthenticationError.serviceKeyResolutionFailed(let attempts) {
            XCTAssertEqual(attempts, [
                .init(source: .appStoreConnectSignOut, failure: .missingRedirect),
                .init(source: .olympus, failure: .httpStatus(code: 404, bodyPreview: "Not Found"))
            ])
            let message = AuthenticationError.serviceKeyResolutionFailed(attempts: attempts).localizedDescription
            XCTAssertTrue(message.contains("sign-out redirect"))
            XCTAssertTrue(message.contains("HTTP 404"))
            XCTAssertTrue(message.contains("Not Found"))
        }
    }

    func testServiceKeyResolverReportsMalformedRedirectAndMissingOlympusKey() async throws {
        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: {
                Self.response(
                    url: .appStoreConnectLogout,
                    statusCode: 302,
                    headers: ["Location": "%"]
                )
            },
            loadOlympusResponse: {
                Self.response(
                    url: URLRequest.olympusServiceKeyFallback.url!,
                    statusCode: 200,
                    headers: ["Content-Type": "application/json"],
                    body: Data(#"{"unrelated":"value"}"#.utf8)
                )
            }
        )

        do {
            _ = try await resolver.serviceKey()
            XCTFail("Expected service-key resolution to fail")
        } catch AuthenticationError.serviceKeyResolutionFailed(let attempts) {
            XCTAssertEqual(attempts, [
                .init(source: .appStoreConnectSignOut, failure: .invalidRedirect),
                .init(source: .olympus, failure: .missingKey)
            ])
        }
    }

    func testServiceKeyFailureIdentifiesRetryableResponses() {
        XCTAssertTrue(AppleServiceKeyFailure.network(description: "offline").isRetryable)
        XCTAssertTrue(AppleServiceKeyFailure.httpStatus(code: 429, bodyPreview: nil).isRetryable)
        XCTAssertTrue(AppleServiceKeyFailure.httpStatus(code: 503, bodyPreview: nil).isRetryable)
        XCTAssertFalse(AppleServiceKeyFailure.httpStatus(code: 404, bodyPreview: nil).isRetryable)
        XCTAssertFalse(AppleServiceKeyFailure.missingKey.isRetryable)
    }

    func testServiceKeyResolverUsesCachedKeyWithoutNetworking() async throws {
        let steps = StepRecorder()
        let cache = AppleServiceKeyCache(
            load: {
                steps.record("cache")
                return " cached-widget-key\n"
            },
            save: { _ in XCTFail("A cached key should not be written again") }
        )
        let resolver = AppleServiceKeyResolver(
            cache: cache,
            loadSignOutResponse: {
                steps.record("signout")
                return Self.signOutResponse(widgetKey: "redirect-widget-key")
            },
            loadOlympusResponse: {
                steps.record("olympus")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        let key = try await resolver.serviceKey()
        XCTAssertEqual(key, "cached-widget-key")
        XCTAssertEqual(steps.values, ["cache"])
    }

    func testServiceKeyResolverCachesFetchedKeyAndReusesItInMemory() async throws {
        let steps = StepRecorder()
        let cache = AppleServiceKeyCache(
            load: { nil },
            save: { key in steps.record("save:\(key)") }
        )
        let resolver = AppleServiceKeyResolver(
            cache: cache,
            loadSignOutResponse: {
                steps.record("signout")
                return Self.signOutResponse(widgetKey: "redirect-widget-key")
            },
            loadOlympusResponse: {
                XCTFail("Olympus should not be used")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        let first = try await resolver.serviceKey()
        let second = try await resolver.serviceKey()

        XCTAssertEqual(first, "redirect-widget-key")
        XCTAssertEqual(second, "redirect-widget-key")
        XCTAssertEqual(steps.values, ["signout", "save:redirect-widget-key"])
    }

    func testServiceKeyResolverDoesNotFailWhenCacheCannotBeReadOrWritten() async throws {
        enum CacheError: Error { case unavailable }

        let resolver = AppleServiceKeyResolver(
            cache: AppleServiceKeyCache(
                load: { throw CacheError.unavailable },
                save: { _ in throw CacheError.unavailable }
            ),
            loadSignOutResponse: {
                Self.signOutResponse(widgetKey: "redirect-widget-key")
            },
            loadOlympusResponse: {
                XCTFail("Olympus should not be used")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        let key = try await resolver.serviceKey()
        XCTAssertEqual(key, "redirect-widget-key")
    }

    func testServiceKeyResolverDoesNotSwallowUnexpectedErrors() async throws {
        enum LocalError: Error, Equatable { case unavailableFile }

        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: { throw LocalError.unavailableFile },
            loadOlympusResponse: {
                XCTFail("Unexpected errors must not fall through to Olympus")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )

        do {
            _ = try await resolver.serviceKey()
            XCTFail("Expected the original error")
        } catch let error as LocalError {
            XCTAssertEqual(error, .unavailableFile)
        }
    }

    func testServiceKeyResolverPropagatesCancellationWithoutTryingOlympus() async throws {
        let steps = StepRecorder()
        let started = AsyncStream<Void>.makeStream()
        let release = AsyncStream<Void>.makeStream()
        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: {
                steps.record("signout")
                started.continuation.yield()
                for await _ in release.stream {
                    break
                }
                return Self.signOutResponse(widgetKey: "redirect-widget-key")
            },
            loadOlympusResponse: {
                steps.record("olympus")
                return Self.olympusResponse(widgetKey: "olympus-widget-key")
            }
        )
        let task = Task {
            try await resolver.serviceKey()
        }
        var startedIterator = started.stream.makeAsyncIterator()
        _ = await startedIterator.next()

        task.cancel()
        release.continuation.yield()

        do {
            _ = try await task.value
            XCTFail("Expected cancellation")
        } catch is CancellationError {
            XCTAssertEqual(steps.values, ["signout"])
        }
        started.continuation.finish()
        release.continuation.finish()
    }

    func testAuthenticationFailureIsNotConvertedIntoServiceKeyResolutionFailure() async throws {
        let client = Client(
            urlSession: MockURLProtocol.session { request in
                Self.emptyResponse(for: request, statusCode: 401)
            },
            serviceKeyProvider: .fixed("test-widget-key")
        )

        do {
            _ = try await client.checkIsFederated(accountName: "test@example.com")
            XCTFail("Expected federation to fail")
        } catch is AuthenticationError {
            XCTFail("The federation error must not be converted into an authentication error")
        } catch {
            XCTAssertFalse(error is CancellationError)
        }
    }

    func testSignOutServiceKeyRequestIsHeadAndDoesNotHandleCookies() {
        let request = URLRequest.appStoreConnectLogoutServiceKey

        XCTAssertEqual(request.httpMethod, "HEAD")
        XCTAssertEqual(request.httpShouldHandleCookies, false)
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
    }

    func testSignOutServiceKeySessionHasNoCookieStoreAndDoesNotFollowRedirects() {
        let session = URLSession.appleServiceKeySignOut

        XCTAssertNil(session.configuration.httpCookieStorage)
        XCTAssertFalse(session.configuration.httpShouldSetCookies)
        XCTAssertEqual(session.configuration.httpCookieAcceptPolicy, .never)
        XCTAssertTrue(session.delegate is NoRedirectURLSessionDelegate)
    }

    func testLiveAppStoreConnectSignOutRedirectContainsServiceKey() async throws {
        guard ProcessInfo.processInfo.environment["XCODES_LOGIN_KIT_LIVE_SERVICE_KEY_TEST"] == "1" else {
            throw XCTSkip("Set XCODES_LOGIN_KIT_LIVE_SERVICE_KEY_TEST=1 to contact App Store Connect")
        }

        let httpClient = AppleServiceKeyHTTPClient(session: .appleServiceKeySignOut)
        let resolver = AppleServiceKeyResolver(
            cache: .disabled,
            loadSignOutResponse: {
                try await httpClient.response(for: .appStoreConnectLogoutServiceKey)
            },
            loadOlympusResponse: {
                XCTFail("The live sign-out redirect should contain the key")
                return Self.olympusResponse(widgetKey: "unexpected-fallback-key")
            }
        )

        let key = try await resolver.serviceKey()

        XCTAssertNotNil(key.wholeMatch(of: /[0-9a-f]{32,64}/))
    }

    func testHashcashRequestIncludesWidgetKey() throws {
        let request = try URLRequest.federate(account: "test@example.com", serviceKey: "test-widget-key")
        let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))

        XCTAssertEqual(components.queryItems?.first(where: { $0.name == "widgetKey" })?.value, "test-widget-key")
    }

    func testAuthenticationStateLoadsExplicitProviderOnlyOnce() async throws {
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
        _ = try await client.authenticationState(accountName: "test@company.com", password: nil)
        let invocationCount = await invocationCounter.value
        XCTAssertEqual(invocationCount, 1)
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
    static func signOutResponse(widgetKey: String) -> (Data, HTTPURLResponse) {
        response(
            url: .appStoreConnectLogout,
            statusCode: 302,
            headers: [
                "Location": "https://idmsa.apple.com/appleauth/signout?widgetKey=\(widgetKey)&asop=destroy-session&asoc=/&rv=3"
            ]
        )
    }

    static func olympusResponse(widgetKey: String) -> (Data, HTTPURLResponse) {
        response(
            url: URLRequest.olympusServiceKeyFallback.url!,
            statusCode: 200,
            headers: ["Content-Type": "application/json"],
            body: Data(#"{"authServiceKey":"\#(widgetKey)"}"#.utf8)
        )
    }

    static func response(
        url: URL,
        statusCode: Int,
        headers: [String: String] = [:],
        body: Data = Data()
    ) -> (Data, HTTPURLResponse) {
        (
            body,
            HTTPURLResponse(
                url: url,
                statusCode: statusCode,
                httpVersion: nil,
                headerFields: headers
            )!
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
