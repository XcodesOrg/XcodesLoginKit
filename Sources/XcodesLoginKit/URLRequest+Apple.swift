//
//  URLRequest+Apple.swift
//  XcodesLoginKit
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import Foundation

public extension URL {
    @available(*, deprecated, message: "This endpoint is unreliable and is retained only as a fallback.")
    static let itcServiceKey = URL(string: "https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com")!
    static let appStoreConnectLogout = URL(string: "https://appstoreconnect.apple.com/logout")!
    static let signIn = URL(string: "https://idmsa.apple.com/appleauth/auth/signin")!
    static let authOptions = URL(string: "https://idmsa.apple.com/appleauth/auth")!
    static let requestSecurityCode = URL(string: "https://idmsa.apple.com/appleauth/auth/verify/phone")!
    static func submitSecurityCode(_ code: SecurityCode) -> URL { URL(string: "https://idmsa.apple.com/appleauth/auth/verify/\(code.urlPathComponent)/securitycode")! }
    static let trust = URL(string: "https://idmsa.apple.com/appleauth/auth/2sv/trust")!
    static let federate = URL(string: "https://idmsa.apple.com/appleauth/auth/federate")!
    static let federateValidate = URL(string: "https://idmsa.apple.com/appleauth/auth/federate/validate")!
    static let olympusSession = URL(string: "https://appstoreconnect.apple.com/olympus/v1/session")!
    static let keyAuth = URL(string: "https://idmsa.apple.com/appleauth/auth/verify/security/key")!
    
    static let srpInit = URL(string: "https://idmsa.apple.com/appleauth/auth/signin/init")!
    static let srpComplete = URL(string: "https://idmsa.apple.com/appleauth/auth/signin/complete?isRememberMeEnabled=false")!
    
}

public extension URLRequest {
    @available(*, deprecated, message: "This endpoint is unreliable and is retained only as a fallback.")
    static var itcServiceKey: URLRequest {
        URLRequest(url: .itcServiceKey)
    }

    static var olympusServiceKeyFallback: URLRequest {
        URLRequest(url: URL(string: "https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com")!)
    }

    static var appStoreConnectLogoutServiceKey: URLRequest {
        var request = URLRequest(url: .appStoreConnectLogout)
        request.httpMethod = "HEAD"
        request.httpShouldHandleCookies = false
        return request
    }

    static func signIn(serviceKey: String, accountName: String, password: String, hashcash: String) -> URLRequest {
        struct Body: Encodable {
            let accountName: String
            let password: String
            let rememberMe = true
        }

        var request = URLRequest(url: .signIn)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.allHTTPHeaderFields?["X-Requested-With"] = "XMLHttpRequest"
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["X-Apple-HC"] = hashcash
        request.allHTTPHeaderFields?["Accept"] = "application/json, text/javascript"
        request.httpMethod = "POST"
        request.httpBody = try! JSONEncoder().encode(Body(accountName: accountName, password: password))
        return request
    }

    static func authOptions(serviceKey: String, sessionID: String, scnt: String) -> URLRequest {
        var request = URLRequest(url: .authOptions)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["X-Apple-ID-Session-Id"] = sessionID
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["scnt"] = scnt
        request.allHTTPHeaderFields?["accept"] = "application/json"
        return request
    }
    
    static func requestSecurityCode(serviceKey: String, sessionID: String, scnt: String, trustedPhoneID: Int) throws -> URLRequest {
        struct Body: Encodable {
            let phoneNumber: PhoneNumber
            let mode = "sms"
            
            struct PhoneNumber: Encodable {
                let id: Int
            }
        }
        
        var request = URLRequest(url: .requestSecurityCode)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.allHTTPHeaderFields?["X-Apple-ID-Session-Id"] = sessionID
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["scnt"] = scnt
        request.allHTTPHeaderFields?["accept"] = "application/json"
        request.httpMethod = "PUT"
        request.httpBody = try JSONEncoder().encode(Body(phoneNumber: .init(id: trustedPhoneID)))
        return request
    }

    static func submitSecurityCode(serviceKey: String, sessionID: String, scnt: String, code: SecurityCode) throws -> URLRequest {
        struct DeviceSecurityCodeRequest: Encodable {
            let securityCode: SecurityCode
            
            struct SecurityCode: Encodable {
                let code: String
            }
        }

        struct SMSSecurityCodeRequest: Encodable {
            let securityCode: SecurityCode
            let phoneNumber: PhoneNumber
            let mode = "sms"
            
            struct SecurityCode: Encodable {
                let code: String
            }
            struct PhoneNumber: Encodable {
                let id: Int
            }
        }

        var request = URLRequest(url: .submitSecurityCode(code))
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["X-Apple-ID-Session-Id"] = sessionID
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["scnt"] = scnt
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.httpMethod = "POST"
        switch code {
        case .device(let code):
            request.httpBody = try JSONEncoder().encode(DeviceSecurityCodeRequest(securityCode: .init(code: code)))
        case .sms(let code, let phoneNumberId):
            request.httpBody = try JSONEncoder().encode(SMSSecurityCodeRequest(securityCode: .init(code: code), phoneNumber: .init(id: phoneNumberId)))
        }
        return request
    }
    
    static func respondToChallenge(serviceKey: String, sessionID: String, scnt: String, response: Data) -> URLRequest {
        var request = URLRequest(url: .keyAuth)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["X-Apple-ID-Session-Id"] = sessionID
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["scnt"] = scnt
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.httpMethod = "POST"
        request.httpBody = response
        return request
    }

    static func trust(serviceKey: String, sessionID: String, scnt: String) -> URLRequest {
        var request = URLRequest(url: .trust)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["X-Apple-ID-Session-Id"] = sessionID
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["scnt"] = scnt
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        return request
    }

    static var olympusSession: URLRequest {
        return URLRequest(url: .olympusSession)
    }
    
    static func federate(account _: String, serviceKey: String) throws -> URLRequest {
        var components = URLComponents(url: .signIn, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "widgetKey", value: serviceKey)]
        var request = URLRequest(url: components.url!)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.httpMethod = "GET"
        return request
    }

    static func checkFederation(serviceKey: String, accountName: String) -> URLRequest {
        struct Body: Encodable {
            let accountName: String
            let rememberMe = true
        }

        var request = URLRequest(url: .federate)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.allHTTPHeaderFields?["X-Requested-With"] = "XMLHttpRequest"
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        request.httpMethod = "POST"
        request.httpBody = try? JSONEncoder().encode(Body(accountName: accountName))
        return request
    }

    static func federateValidate(widgetKey: String, token: String, relayState: String) -> URLRequest {
        var components = URLComponents(url: .federateValidate, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "widgetKey", value: widgetKey),
            URLQueryItem(name: "token", value: token),
            URLQueryItem(name: "relayState", value: relayState)
        ]
        var request = URLRequest(url: components.url!)
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        return request
    }
    
    static func SRPInit(serviceKey: String, a: String, accountName: String) -> URLRequest {
        struct ServerSRPInitRequest: Encodable {
            public let a: String
            public let accountName: String
            public let protocols: [SRPProtocol]
        }
        
        var request = URLRequest(url: .srpInit)
        request.httpMethod = "POST"
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.allHTTPHeaderFields?["X-Requested-With"] = "XMLHttpRequest"
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        
        request.httpBody = try? JSONEncoder().encode(ServerSRPInitRequest(a: a, accountName: accountName, protocols: [.s2k, .s2k_fo]))
        return request
    }
    
    static func SRPComplete(serviceKey: String, hashcash: String, accountName: String, c: String, m1: String, m2: String) -> URLRequest {
        struct ServerSRPCompleteRequest: Encodable {
            let accountName: String
            let c: String
            let m1: String
            let m2: String
            let rememberMe: Bool
        }
        
        var request = URLRequest(url: .srpComplete)
        request.httpMethod = "POST"
        request.allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        request.allHTTPHeaderFields?["Accept"] = "application/json"
        request.allHTTPHeaderFields?["Content-Type"] = "application/json"
        request.allHTTPHeaderFields?["X-Requested-With"] = "XMLHttpRequest"
        request.allHTTPHeaderFields?["X-Apple-Widget-Key"] = serviceKey
        request.allHTTPHeaderFields?["X-Apple-HC"] = hashcash
        
        request.httpBody = try? JSONEncoder().encode(ServerSRPCompleteRequest(accountName: accountName, c: c, m1: m1, m2: m2, rememberMe: false))
        return request
    }
}

public enum SRPProtocol: String, Codable, Sendable {
    case s2k, s2k_fo
}
