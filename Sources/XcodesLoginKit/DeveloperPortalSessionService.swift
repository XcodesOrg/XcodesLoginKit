import Foundation

public struct DeveloperPortalSessionService: Sendable {
    public typealias LoadData = @Sendable (URLRequest) async throws -> (Data, URLResponse)
    public typealias UnauthorizedError = @Sendable () -> Error

    private let loadData: LoadData
    private let unauthorizedError: UnauthorizedError

    public init(
        loadData: @escaping LoadData,
        unauthorizedError: @escaping UnauthorizedError = { AuthenticationError.notAuthorized }
    ) {
        self.loadData = loadData
        self.unauthorizedError = unauthorizedError
    }

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
