import Foundation
import os

/// Resolves and caches Apple's public App Store Connect sign-in service key.
actor AppleServiceKeyResolver {
    typealias ResponseLoader = @Sendable () async throws -> (Data, HTTPURLResponse)

    private static let logger = Logger(
        subsystem: "org.xcodes.XcodesLoginKit",
        category: "AppleServiceKey"
    )

    private let provider: AppleServiceKeyProvider?
    private let cache: AppleServiceKeyCache
    private let loadSignOutResponse: ResponseLoader
    private let loadOlympusResponse: ResponseLoader
    private var memoryKey: String?

    init(
        provider: AppleServiceKeyProvider? = nil,
        cache: AppleServiceKeyCache = .default,
        loadSignOutResponse: @escaping ResponseLoader,
        loadOlympusResponse: @escaping ResponseLoader
    ) {
        self.provider = provider
        self.cache = cache
        self.loadSignOutResponse = loadSignOutResponse
        self.loadOlympusResponse = loadOlympusResponse
    }

    static func live(
        provider: AppleServiceKeyProvider?,
        authenticationSession: URLSession
    ) -> AppleServiceKeyResolver {
        let signOutClient = AppleServiceKeyHTTPClient(session: .appleServiceKeySignOut)
        let olympusClient = AppleServiceKeyHTTPClient(session: authenticationSession)

        return AppleServiceKeyResolver(
            provider: provider,
            loadSignOutResponse: {
                try await signOutClient.response(for: .appStoreConnectLogoutServiceKey)
            },
            loadOlympusResponse: {
                try await olympusClient.response(for: .olympusServiceKeyFallback)
            }
        )
    }

    func serviceKey() async throws -> String {
        var attempts: [AppleServiceKeyAttempt] = []

        if let memoryKey {
            return memoryKey
        }

        if let provider {
            do {
                let suppliedKey = try await provider.serviceKey()
                try Task.checkCancellation()

                if let key = normalized(suppliedKey) {
                    memoryKey = key
                    return key
                }
                attempts.append(.init(source: .supplied, failure: .missingKey))
            } catch {
                try Task.checkCancellation()
                if let failure = Self.expectedFailure(from: error) {
                    attempts.append(.init(source: .supplied, failure: failure))
                } else {
                    throw error
                }
            }
        }

        do {
            if let cachedKey = try cache.load().flatMap(normalized) {
                memoryKey = cachedKey
                return cachedKey
            }
        } catch {
            Self.logger.warning("Could not read the cached Apple service key: \(error.localizedDescription, privacy: .public)")
        }

        do {
            let response = try await loadSignOutResponse()
            try Task.checkCancellation()

            switch Self.keyFromSignOutResponse(response) {
            case let .success(key):
                return store(key)
            case let .failure(failure):
                attempts.append(.init(source: .appStoreConnectSignOut, failure: failure))
            }
        } catch {
            try Task.checkCancellation()
            if let failure = Self.expectedFailure(from: error) {
                attempts.append(.init(source: .appStoreConnectSignOut, failure: failure))
            } else {
                throw error
            }
        }

        do {
            let response = try await loadOlympusResponse()
            try Task.checkCancellation()

            switch Self.keyFromOlympusResponse(response) {
            case let .success(key):
                return store(key)
            case let .failure(failure):
                attempts.append(.init(source: .olympus, failure: failure))
            }
        } catch {
            try Task.checkCancellation()
            if let failure = Self.expectedFailure(from: error) {
                attempts.append(.init(source: .olympus, failure: failure))
            } else {
                throw error
            }
        }

        throw AuthenticationError.serviceKeyResolutionFailed(attempts: attempts)
    }

    private func store(_ key: String) -> String {
        memoryKey = key
        do {
            try cache.save(key)
        } catch {
            Self.logger.warning("Could not cache the Apple service key: \(error.localizedDescription, privacy: .public)")
        }
        return key
    }

    private func normalized(_ key: String) -> String? {
        Self.normalizedStatic(key)
    }

    private static func keyFromSignOutResponse(
        _ response: (Data, HTTPURLResponse)
    ) -> Result<String, AppleServiceKeyFailure> {
        let (_, httpResponse) = response
        guard 300..<400 ~= httpResponse.statusCode else {
            return .failure(.httpStatus(code: httpResponse.statusCode, bodyPreview: nil))
        }
        guard let location = httpResponse.value(forHTTPHeaderField: "Location"), !location.isEmpty else {
            return .failure(.missingRedirect)
        }
        guard let components = URLComponents(string: location),
              let redirectURL = components.url,
              redirectURL.scheme != nil,
              redirectURL.host != nil else {
            return .failure(.invalidRedirect)
        }
        guard let key = components.queryItems?.first(where: { $0.name == "widgetKey" })?.value,
              let key = normalizedStatic(key) else {
            return .failure(.missingKey)
        }
        return .success(key)
    }

    private static func keyFromOlympusResponse(
        _ response: (Data, HTTPURLResponse)
    ) -> Result<String, AppleServiceKeyFailure> {
        let (data, httpResponse) = response
        guard 200..<300 ~= httpResponse.statusCode else {
            return .failure(.httpStatus(
                code: httpResponse.statusCode,
                bodyPreview: bodyPreview(data)
            ))
        }

        guard let response = try? JSONDecoder().decode(ServiceKeyResponse.self, from: data),
              let key = normalizedStatic(response.authServiceKey) else {
            return .failure(.missingKey)
        }
        return .success(key)
    }

    private static func expectedFailure(from error: Error) -> AppleServiceKeyFailure? {
        if let error = error as? URLError {
            return .network(description: error.localizedDescription)
        }
        if error is AppleServiceKeyTransportError {
            return .invalidResponse
        }
        return nil
    }

    private static func normalizedStatic(_ key: String) -> String? {
        let key = key.trimmingCharacters(in: .whitespacesAndNewlines)
        return key.isEmpty ? nil : key
    }

    private static func bodyPreview(_ data: Data) -> String? {
        guard let body = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !body.isEmpty else {
            return nil
        }
        return String(body.prefix(200))
    }
}

struct AppleServiceKeyCache: Sendable {
    typealias Load = @Sendable () throws -> String?
    typealias Save = @Sendable (String) throws -> Void

    let load: Load
    let save: Save

    static let disabled = AppleServiceKeyCache(load: { nil }, save: { _ in })

    static let `default`: AppleServiceKeyCache = {
        guard let cachesDirectory = FileManager.default.urls(
            for: .cachesDirectory,
            in: .userDomainMask
        ).first else {
            return .disabled
        }

        let directory = cachesDirectory.appendingPathComponent(
            "org.xcodes.XcodesLoginKit",
            isDirectory: true
        )
        let fileURL = directory.appendingPathComponent("apple-service-key.txt")

        return AppleServiceKeyCache(
            load: {
                guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
                return try String(contentsOf: fileURL, encoding: .utf8)
            },
            save: { key in
                try FileManager.default.createDirectory(
                    at: directory,
                    withIntermediateDirectories: true
                )
                try key.write(to: fileURL, atomically: true, encoding: .utf8)
            }
        )
    }()
}

struct AppleServiceKeyHTTPClient: Sendable {
    let session: URLSession

    func response(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else {
            throw AppleServiceKeyTransportError.invalidResponse
        }
        return (data, response)
    }
}

private enum AppleServiceKeyTransportError: Error {
    case invalidResponse
}

/// Stateless; `@unchecked Sendable` is required because `NSObject` does not provide a checked
/// `Sendable` conformance for Foundation delegate implementations.
final class NoRedirectURLSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

extension URLSession {
    static let appleServiceKeySignOut: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(
            configuration: configuration,
            delegate: NoRedirectURLSessionDelegate(),
            delegateQueue: nil
        )
    }()
}

private struct ServiceKeyResponse: Decodable, Sendable {
    let authServiceKey: String
}
