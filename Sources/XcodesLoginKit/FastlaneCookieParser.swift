import Foundation
import Yams

public final class FastlaneCookieParser: Sendable {
    public init() {}

    public func parse(cookieString: String) throws -> [HTTPCookie] {
        let fixed = cookieString.replacingOccurrences(of: "\\n", with: "\n")
        let cookies = try YAMLDecoder().decode([FastlaneCookie].self, from: fixed)
        return cookies.compactMap(\.httpCookie)
    }
}

private struct FastlaneCookie: Decodable {
    enum CodingKeys: String, CodingKey {
        case name
        case value
        case domain
        case forDomain = "for_domain"
        case path
        case secure
        case expires
        case maxAge = "max_age"
        case createdAt = "created_at"
        case accessedAt = "accessed_at"
    }

    let name: String
    let value: String
    let domain: String
    let forDomain: Bool
    let path: String
    let secure: Bool
    let expires: Date?
    let maxAge: Int?
    let createdAt: Date
    let accessedAt: Date
}

private protocol HTTPCookieConvertible {
    var httpCookie: HTTPCookie? { get }
}

extension FastlaneCookie: HTTPCookieConvertible {
    var httpCookie: HTTPCookie? {
        var properties: [HTTPCookiePropertyKey: Any] = [
            .name: name,
            .value: value,
            .domain: domain,
            .path: path,
            .secure: secure,
        ]

        if forDomain {
            properties[.domain] = ".\(domain)"
        } else {
            properties[.domain] = domain
        }

        if let expires {
            properties[.expires] = expires
        }

        if let maxAge {
            properties[.maximumAge] = maxAge
        }

        return HTTPCookie(properties: properties)
    }
}
