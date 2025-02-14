import Foundation
import AsyncNetworkService


struct Environment: Sendable {
    var network = Network()
}

@MainActor
var Current = Environment()

public struct Network: Sendable {
    public var session: URLSession {
        networkService.urlSession
    }
    // Shared URL Session so we can save and grab some headers to use later
    @preconcurrency
    let networkService = AsyncHTTPNetworkService(urlSession: URLSession.shared)
    

//    public var dataTask: (URLRequest) -> URLSession.DataTaskPublisher = { Current.network.session.dataTaskPublisher(for: $0) }
//    public func dataTask(with request: URLRequest) -> URLSession.DataTaskPublisher {
//        dataTask(request)
//    }
}
