//
//  AuthenticationState.swift
//  XcodesLoginKit
//
//  Created by Matt Kiazyk on 2025-01-31.
//


import Foundation

/// Describes the next step, or final result, of an Apple authentication flow.
///
/// `Client` methods return this value so callers can present the right UI for federated sign-in,
/// two-factor authentication, or a completed Apple Developer session.
public enum AuthenticationState: Equatable, Sendable {
    /// No authenticated Apple session is available.
    case unauthenticated
    /// The Apple ID belongs to an organization that requires browser-based identity-provider sign-in.
    case waitingForFederatedAuthentication(FederationResponse)
    /// Apple requires an additional trusted-device, SMS, or security-key verification step.
    case waitingForSecondFactor(TwoFactorOption, AuthOptionsResponse, AppleSessionData)
    /// Authentication succeeded and the client has a valid Apple session.
    case authenticated(AppleSession)
    /// The signed-in Apple ID is not registered for the Apple Developer Program.
    case notAppleDeveloper
}

/// The type of second-factor challenge Apple expects the caller to complete.
public enum TwoFactorOption: Equatable, Sendable {
    /// An SMS code has already been sent to the provided phone number.
    case smsSent(AuthOptionsResponse.TrustedPhoneNumber)
    /// A code was sent to one of the account's trusted devices.
    case codeSent
    /// The user must choose a trusted phone number before an SMS can be sent.
    case smsPendingChoice
    /// The user must respond with a physical security key.
    case securityKey
}

@preconcurrency
/// Apple's available second-factor options for the current login attempt.
public struct AuthOptionsResponse: Equatable, Decodable, Sendable {
    /// Trusted phone numbers that can receive an SMS code.
    public let trustedPhoneNumbers: [TrustedPhoneNumber]?
    /// Trusted devices that can display a verification code.
    public let trustedDevices: [TrustedDevice]?
    /// Metadata about the expected verification code.
    public let securityCode: SecurityCodeInfo?
    /// Whether Apple reports that no trusted devices are available.
    public let noTrustedDevices: Bool?
    /// Service errors returned by Apple's authentication API.
    public let serviceErrors: [ServiceError]?
    /// Security-key challenge data, when the account requires an FSA challenge.
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
    
    /// The inferred second-factor family represented by this response.
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
    /// Whether the user can receive a verification code by SMS.
    public var canFallBackToSMS: Bool {
        noTrustedDevices == true
    }
    
    /// Whether Apple already sent an SMS code without requiring the user to choose a phone number.
    public var smsAutomaticallySent: Bool {
        trustedPhoneNumbers?.count == 1 && canFallBackToSMS
    }
    
    /// A trusted phone number that can receive an SMS verification code.
    public struct TrustedPhoneNumber: Equatable, Decodable, Identifiable, Sendable {
        /// Apple's identifier for the phone number.
        public let id: Int
        /// A display-ready masked or formatted phone number with its dial code.
        public let numberWithDialCode: String

        public init(id: Int, numberWithDialCode: String) {
            self.id = id
            self.numberWithDialCode = numberWithDialCode
        }
    }
    
    /// A trusted device that can display an Apple verification code.
    public struct TrustedDevice: Equatable, Decodable, Sendable  {
        /// Apple's identifier for the device.
        public let id: String
        /// The user-visible device name.
        public let name: String
        /// The device model name.
        public let modelName: String

        public init(id: String, name: String, modelName: String) {
            self.id = id
            self.name = name
            self.modelName = modelName
        }
    }
    
    /// Metadata and rate-limit state for an Apple verification code.
    public struct SecurityCodeInfo: Equatable, Decodable, Sendable  {
        /// The expected number of digits in the verification code.
        public let length: Int
        /// Whether too many codes have been sent.
        public let tooManyCodesSent: Bool
        /// Whether too many submitted codes have failed validation.
        public let tooManyCodesValidated: Bool
        /// Whether verification-code entry is locked.
        public let securityCodeLocked: Bool
        /// Whether Apple requires a cooldown before sending or validating another code.
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
    
    /// The broad authentication challenge family represented by an auth-options response.
    public enum Kind: Equatable, Sendable {
        case twoStep, twoFactor, securityKey, unknown
    }
}

/// Apple headers and service key needed to continue a second-factor login attempt.
public struct AppleSessionData: Equatable, Identifiable, Sendable {
    /// The Apple authentication service key for the current flow.
    public let serviceKey: String
    /// The `X-Apple-ID-Session-Id` header value.
    public let sessionID: String
    /// The `scnt` header value.
    public let scnt: String
    
    /// A stable identifier for UI lists and SwiftUI state.
    public var id: String { sessionID }

    public init(serviceKey: String, sessionID: String, scnt: String) {
        self.serviceKey = serviceKey
        self.sessionID = sessionID
        self.scnt = scnt
    }
}

/// A service error returned by Apple's authentication endpoints.
public struct ServiceError: Decodable, Equatable, Sendable  {
    let code: String
    let message: String
}

/// Challenge data used by Apple's FSA/security-key flow.
public struct FSAChallenge: Equatable, Decodable, Sendable {
    /// The base64url-encoded challenge from Apple.
    public let challenge: String
    /// Allowed key handles for the security-key assertion.
    public let keyHandles: [String]
    /// A comma-separated list of allowed credential identifiers.
    public let allowedCredentials: String
}

/// A verification code submitted during two-factor authentication.
public enum SecurityCode: Sendable {
    /// A code displayed on a trusted Apple device.
    case device(code: String)
    /// A code received by SMS for a specific trusted phone number.
    case sms(code: String, phoneNumberId: Int)
    
    /// The URL path component Apple expects for this code type.
    public var urlPathComponent: String {
        switch self {
        case .device: return "trusteddevice"
        case .sms: return "phone"
        }
    }
}

struct SignInResponse: Decodable, Sendable {
    let authType: String?
    let serviceErrors: [ServiceError]?
    
    struct ServiceError: Decodable, CustomStringConvertible, Sendable {
        let code: String
        let message: String
        
        var description: String {
            return "\(code): \(message)"
        }
    }
}

/// Apple's SRP initialization response.
public struct ServerSRPInitResponse: Decodable, Sendable {
    let iteration: Int
    let salt: String
    let b: String
    let c: String
    let `protocol`: SRPProtocol
}

/// A validated Apple session.
public struct AppleSession: Decodable, Sendable, Equatable {
    /// User information associated with the session.
    public let user: AppleSessionUser
}

/// User information returned by Apple's session endpoint.
public struct AppleSessionUser: Decodable, Sendable, Equatable {
    /// The user's full name, when Apple returns it.
    public let fullName: String?
}

/// Describes whether an Apple ID is federated and how to begin identity-provider sign-in.
public struct FederationResponse: Decodable, Equatable, Sendable {
    /// Whether the Apple ID uses federated authentication.
    public let federated: Bool
    /// Whether Apple expects an identity-provider confirmation screen.
    public let showFederatedIdpConfirmation: Bool?
    /// The identity-provider URL and request parameters.
    public let federatedIdpRequest: FederatedIdpRequest?
    /// Organization and identity-provider display information.
    public let federatedAuthIntro: FederatedAuthIntro?

    public init(
        federated: Bool,
        showFederatedIdpConfirmation: Bool? = nil,
        federatedIdpRequest: FederatedIdpRequest? = nil,
        federatedAuthIntro: FederatedAuthIntro? = nil
    ) {
        self.federated = federated
        self.showFederatedIdpConfirmation = showFederatedIdpConfirmation
        self.federatedIdpRequest = federatedIdpRequest
        self.federatedAuthIntro = federatedAuthIntro
    }

    /// A ready-to-open identity-provider URL containing Apple's request parameters.
    public var idpURL: URL? {
        guard let idpRequest = federatedIdpRequest else { return nil }
        var components = URLComponents(string: idpRequest.idPUrl)
        components?.queryItems = idpRequest.requestParams.map { key, value in
            URLQueryItem(name: key, value: value)
        }
        return components?.url
    }
}

/// Identity-provider request data returned for a federated Apple ID.
public struct FederatedIdpRequest: Decodable, Equatable, Sendable {
    /// The identity-provider endpoint URL string.
    public let idPUrl: String
    /// Query parameters to include when opening the identity-provider URL.
    public let requestParams: [String: String]
    /// The HTTP method Apple describes for the identity-provider request.
    public let httpMethod: String?

    public init(idPUrl: String, requestParams: [String: String], httpMethod: String?) {
        self.idPUrl = idPUrl
        self.requestParams = requestParams
        self.httpMethod = httpMethod
    }
}

/// Display metadata for a federated organization's sign-in flow.
public struct FederatedAuthIntro: Decodable, Equatable, Sendable {
    /// The organization name.
    public let orgName: String?
    /// The identity-provider display name.
    public let idpName: String?
    /// The identity-provider URL string.
    public let idpUrl: String?
    /// Apple's organization type label.
    public let orgType: String?
    /// A URL where the user can manage the federated account.
    public let accountManagementUrl: String?

    public init(orgName: String?, idpName: String?, idpUrl: String?, orgType: String?, accountManagementUrl: String?) {
        self.orgName = orgName
        self.idpName = idpName
        self.idpUrl = idpUrl
        self.orgType = orgType
        self.accountManagementUrl = accountManagementUrl
    }
}

/// Values extracted from the browser callback URL after federated sign-in.
///
/// Create this from the URL a user is redirected to after identity-provider sign-in, then pass the
/// extracted values to ``Client/validateFederatedToken(widgetKey:token:relayState:)``.
public struct FederatedAuthenticationCallback: Equatable, Sendable {
    /// Apple's widget key for the federated authentication flow.
    public let widgetKey: String
    /// The federated authentication token.
    public let token: String
    /// The relay state returned by the identity provider.
    public let relayState: String

    /// Parses callback values from a federated authentication redirect URL.
    public init(callbackURL: URL) throws {
        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            throw AuthenticationError.invalidFederatedAuthenticationCallback
        }

        guard let widgetKey = queryItems.first(where: { $0.name == "widgetKey" })?.value,
              let token = queryItems.first(where: { $0.name == "token" })?.value,
              let relayState = queryItems.first(where: { $0.name == "relayState" })?.value else {
            throw AuthenticationError.invalidFederatedAuthenticationCallback
        }

        self.widgetKey = widgetKey
        self.token = token
        self.relayState = relayState
    }

    /// Parses callback values from a federated authentication redirect URL string.
    public init(callbackURLString: String) throws {
        guard let callbackURL = URL(string: callbackURLString) else {
            throw AuthenticationError.invalidFederatedAuthenticationCallback
        }

        try self.init(callbackURL: callbackURL)
    }
}
