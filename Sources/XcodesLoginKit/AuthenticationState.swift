//
//  AuthenticationState.swift
//  XcodesLoginKit
//
//  Created by Matt Kiazyk on 2025-01-31.
//


public enum AuthenticationState: Equatable, Sendable {
    case unauthenticated
    case waitingForSecondFactor(TwoFactorOption, AuthOptionsResponse, AppleSessionData)
    case authenticated(AppleSession)
    case notAppleDeveloper
}

public enum TwoFactorOption: Equatable, Sendable {
    case smsSent(AuthOptionsResponse.TrustedPhoneNumber)
    case codeSent
    case smsPendingChoice
    case securityKey
}

@preconcurrency
public struct AuthOptionsResponse: Equatable, Decodable, Sendable {
    public let trustedPhoneNumbers: [TrustedPhoneNumber]?
    public let trustedDevices: [TrustedDevice]?
    public let securityCode: SecurityCodeInfo?
    public let noTrustedDevices: Bool?
    public let serviceErrors: [ServiceError]?
    public let fsaChallenge: FSAChallenge?
    
    public init(
        trustedPhoneNumbers: [AuthOptionsResponse.TrustedPhoneNumber]?,
        trustedDevices: [AuthOptionsResponse.TrustedDevice]?,
        securityCode: AuthOptionsResponse.SecurityCodeInfo,
        noTrustedDevices: Bool? = nil,
        serviceErrors: [ServiceError]? = nil,
        fsaChallenge: FSAChallenge? = nil
    ) {
        self.trustedPhoneNumbers = trustedPhoneNumbers
        self.trustedDevices = trustedDevices
        self.securityCode = securityCode
        self.noTrustedDevices = noTrustedDevices
        self.serviceErrors = serviceErrors
        self.fsaChallenge = fsaChallenge
    }
    
    public var kind: Kind {
        if trustedDevices != nil {
            return .twoStep
        } else if trustedPhoneNumbers != nil {
            return .twoFactor
        } else if fsaChallenge != nil {
            return .securityKey
        } else {
            return .unknown
        }
    }
    
    // One time with a new testing account I had a response where noTrustedDevices was nil, but the account didn't have any trusted devices.
    // This should have been a situation where an SMS security code was sent automatically.
    // This resolved itself either after some time passed, or by signing into appleid.apple.com with the account.
    // Not sure if it's worth explicitly handling this case or if it'll be really rare.
    public var canFallBackToSMS: Bool {
        noTrustedDevices == true
    }
    
    public var smsAutomaticallySent: Bool {
        trustedPhoneNumbers?.count == 1 && canFallBackToSMS
    }
    
    public struct TrustedPhoneNumber: Equatable, Decodable, Identifiable, Sendable {
        public let id: Int
        public let numberWithDialCode: String

        public init(id: Int, numberWithDialCode: String) {
            self.id = id
            self.numberWithDialCode = numberWithDialCode
        }
    }
    
    public struct TrustedDevice: Equatable, Decodable, Sendable  {
        public let id: String
        public let name: String
        public let modelName: String

        public init(id: String, name: String, modelName: String) {
            self.id = id
            self.name = name
            self.modelName = modelName
        }
    }
    
    public struct SecurityCodeInfo: Equatable, Decodable, Sendable  {
        public let length: Int
        public let tooManyCodesSent: Bool
        public let tooManyCodesValidated: Bool
        public let securityCodeLocked: Bool
        public let securityCodeCooldown: Bool

        public init(
            length: Int,
            tooManyCodesSent: Bool = false,
            tooManyCodesValidated: Bool = false,
            securityCodeLocked: Bool = false,
            securityCodeCooldown: Bool = false
        ) {
            self.length = length
            self.tooManyCodesSent = tooManyCodesSent
            self.tooManyCodesValidated = tooManyCodesValidated
            self.securityCodeLocked = securityCodeLocked
            self.securityCodeCooldown = securityCodeCooldown
        }
    }
    
    public enum Kind: Equatable {
        case twoStep, twoFactor, securityKey, unknown
    }
}

public struct AppleSessionData: Equatable, Identifiable, Sendable {
    public let serviceKey: String
    public let sessionID: String
    public let scnt: String
    
    public var id: String { sessionID }

    public init(serviceKey: String, sessionID: String, scnt: String) {
        self.serviceKey = serviceKey
        self.sessionID = sessionID
        self.scnt = scnt
    }
}

public struct ServiceError: Decodable, Equatable, Sendable  {
    let code: String
    let message: String
}

public struct FSAChallenge: Equatable, Decodable, Sendable {
    public let challenge: String
    public let keyHandles: [String]
    public let allowedCredentials: String
}

public enum SecurityCode {
    case device(code: String)
    case sms(code: String, phoneNumberId: Int)
    
    public var urlPathComponent: String {
        switch self {
        case .device: return "trusteddevice"
        case .sms: return "phone"
        }
    }
}

struct ServiceKeyResponse: Decodable {
    let authServiceKey: String
}

struct SignInResponse: Decodable {
    let authType: String?
    let serviceErrors: [ServiceError]?
    
    struct ServiceError: Decodable, CustomStringConvertible {
        let code: String
        let message: String
        
        var description: String {
            return "\(code): \(message)"
        }
    }
}

public struct ServerSRPInitResponse: Decodable, Sendable {
    let iteration: Int
    let salt: String
    let b: String
    let c: String
    let `protocol`: SRPProtocol
}

public struct AppleSession: Decodable, Sendable, Equatable {
    public let user: AppleSessionUser
}

public struct AppleSessionUser: Decodable, Sendable, Equatable {
    public let fullName: String?
}
