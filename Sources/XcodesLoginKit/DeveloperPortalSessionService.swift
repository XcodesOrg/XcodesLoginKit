import Foundation

/// Validates whether the current Apple cookies can access Apple Developer download services.
///
/// This small service is useful after login when a caller needs to confirm that the Apple ID is
/// authorized for a specific developer download path.
public struct DeveloperPortalSessionService: Sendable {
    /// Loads data for a request and returns its response.
    public typealias LoadData = @Sendable (URLRequest) async throws -> (Data, URLResponse)
    /// Creates the error thrown for unauthorized developer-portal responses.
    public typealias UnauthorizedError = @Sendable () -> Error

    private let loadData: LoadData
    private let unauthorizedError: UnauthorizedError

    /// Creates a developer-portal validation service.
    /// - Parameters:
    ///   - loadData: The networking function used to perform validation.
    ///   - unauthorizedError: The error thrown when Apple returns HTTP 401.
    public init(
        loadData: @escaping LoadData,
        unauthorizedError: @escaping UnauthorizedError = { AuthenticationError.notAuthorized }
    ) {
        self.loadData = loadData
        self.unauthorizedError = unauthorizedError
    }

    /// Validates authorization for an Apple Developer download path.
    ///
    /// A `401` response throws `unauthorizedError`; other HTTP responses are treated as a completed
    /// validation request.
    /// - Parameter path: The path query value for Apple's download authorization endpoint.
    public func validateADCSession(path: String) async throws {
        let (_, response) = try await loadData(.developerDownloadADCAuth(path: path))

        guard let httpResponse = response as? HTTPURLResponse else {
            return
        }

        if httpResponse.statusCode == 401 {
            throw unauthorizedError()
        }
    }
}

private extension URL {
    static let developerDownloadADCAuth = URL(string: "https://developerservices2.apple.com/services/download")!
}

private extension URLRequest {
    static func developerDownloadADCAuth(path: String) -> URLRequest {
        var components = URLComponents(url: .developerDownloadADCAuth, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "path", value: path)]
        var request = URLRequest(url: components.url!)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Accept"] = "*/*"
        return request
    }
}
