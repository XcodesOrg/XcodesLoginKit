//
//  Client.swift
//  XcodesLoginKit
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import AsyncNetworkService
import Foundation
import Crypto
import CommonCrypto
import SRP

/// Performs Apple Developer authentication requests and manages the cookies for those requests.
///
/// `Client` is the low-level API for apps that want to drive their own sign-in UI. Call
/// ``authenticationState(accountName:password:)`` to begin a sign-in attempt, then switch on the
/// returned ``AuthenticationState`` to handle federated authentication or second-factor challenges.
/// The client stores successful authentication cookies in the `URLSession` passed to ``init(urlSession:)``.
public final class Client: Sendable {
    private static let authTypes = ["sa", "hsa", "non-sa", "hsa2"]
    
    private let networkService: AsyncHTTPNetworkService
    
    /// Creates a client that uses the supplied URL session for all Apple authentication requests.
    ///
    /// Use a custom session when you need isolated cookie storage, imported fastlane cookies, or
    /// test-controlled networking. The session's cookie storage is where authenticated Apple cookies
    /// are read and written.
    /// - Parameter urlSession: The session used for requests and cookie persistence.
    public init(urlSession: URLSession = .shared) {
        self.networkService = AsyncHTTPNetworkService(urlSession: urlSession)
    }
    
    /// The URL session used by the client.
    ///
    /// Inspect this when you need direct access to the session's cookie storage after login.
    public var urlSession: URLSession {
        return networkService.urlSession
    }
   
    // MARK: Login

    /// Starts authentication for an Apple ID and returns the next state in the login flow.
    ///
    /// For federated Apple IDs this returns ``AuthenticationState/waitingForFederatedAuthentication(_:)``
    /// without requiring a password. For non-federated Apple IDs, pass a password so the client can
    /// perform SRP authentication. A successful password login may still return a second-factor state
    /// that your app must complete with ``requestSMSSecurityCode(to:authOptions:sessionData:)`` or
    /// ``submitSecurityCode(_:sessionData:)``.
    /// - Parameters:
    ///   - accountName: The Apple ID email address.
    ///   - password: The Apple ID password, or `nil` when checking for federated authentication first.
    /// - Returns: The current authentication state.
    public func authenticationState(accountName: String, password: String?) async throws -> AuthenticationState {
        let federationResponse = try await checkIsFederated(accountName: accountName)
        if federationResponse.federated {
            return .waitingForFederatedAuthentication(federationResponse)
        }

        guard let password, !password.isEmpty else {
            throw AuthenticationError.missingPasswordForNonFederatedAccount
        }

        return try await srpLogin(accountName: accountName, password: password)
    }
    
    /// Signs in a non-federated Apple ID with Secure Remote Password authentication.
    ///
    /// Most callers should use ``authenticationState(accountName:password:)`` so federated accounts are
    /// detected before attempting password authentication.
    /// - Parameters:
    ///   - accountName: The Apple ID email address.
    ///   - password: The Apple ID password.
    /// - Returns: `.authenticated` when no additional verification is needed, or a second-factor state.
    public func srpLogin(accountName: String, password: String) async throws -> AuthenticationState {
        let client = SRPClient(configuration: SRPConfiguration<SHA256>(.N2048))
        let clientKeys = client.generateKeys()
        let a = clientKeys.public
        
        
        let serviceKeyResponse: ServiceKeyResponse = try await networkService.requestObject(URLRequest.itcServiceKey)
        let serviceKey = serviceKeyResponse.authServiceKey
        
        // Fixes issue https://github.com/RobotsAndPencils/XcodesApp/issues/360
        // On 2023-02-23, Apple added a custom implementation of hashcash to their auth flow
        // Without this addition, Apple ID's would get set to locked
        let hashcash = try await loadHashcash(accountName: accountName, serviceKey: serviceKey)
        
        let srp: ServerSRPInitResponse = try await networkService.requestObject(URLRequest.SRPInit(serviceKey: serviceKey, a: Data(a.bytes).base64EncodedString(), accountName: accountName))
        
        // SRP
        guard let decodedB = Data(base64Encoded: srp.b) else {
            throw AuthenticationError.srpInvalidPublicKey
        }
        
        guard let decodedSalt = Data(base64Encoded: srp.salt) else {
            throw AuthenticationError.srpInvalidPublicKey
        }
        
        guard let encryptedPassword = self.pbkdf2(password: password, saltData: decodedSalt, keyByteCount: 32, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: srp.iteration, protocol: srp.protocol) else {
            throw AuthenticationError.srpInvalidPublicKey
        }
        
        let sharedSecret = try client.calculateSharedSecret(password: encryptedPassword, salt: [UInt8](decodedSalt), clientKeys: clientKeys, serverPublicKey: .init([UInt8](decodedB)))
        
        let m1 = client.calculateClientProof(username: accountName, salt: [UInt8](decodedSalt), clientPublicKey: a, serverPublicKey: .init([UInt8](decodedB)), sharedSecret: .init(sharedSecret.bytes))
        let m2 = client.calculateServerProof(clientPublicKey: a, clientProof: m1, sharedSecret: .init([UInt8](sharedSecret.bytes)))

        let result: (Data, URLResponse) = try await networkService.requestData(URLRequest.SRPComplete(serviceKey: serviceKey, hashcash: hashcash, accountName: accountName, c: srp.c, m1: Data(m1).base64EncodedString(), m2: Data(m2).base64EncodedString()), validators: [])
        
        guard let httpResponse = result.1 as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }
        let data = result.0
        
        var responseBody: SignInResponse
        do {
            responseBody = try JSONDecoder.networkJSONDecoder.decode(SignInResponse.self, from: data)
        } catch {
            throw NetworkError.decoding(error: error)
        }
        
        
        switch httpResponse.statusCode {
        case 200:
            return try await self.validateSession()
        case 401:
            throw AuthenticationError.invalidUsernameOrPassword(username: accountName)
        case 403:
            let errorMessage = responseBody.serviceErrors?.first?.description.replacingOccurrences(of: "-20209: ", with: "") ?? ""
            throw AuthenticationError.accountLocked(errorMessage)
        case 409:
            return try await self.handleTwoStepOrFactor(data: data, response: httpResponse, serviceKey: serviceKey)
        case 412 where Client.authTypes.contains(responseBody.authType ?? ""):
            throw AuthenticationError.appleIDAndPrivacyAcknowledgementRequired
        default:
            throw AuthenticationError.unexpectedSignInResponse(statusCode: httpResponse.statusCode,
                                                 message: responseBody.serviceErrors?.map { $0.description }.joined(separator: ", "))
        }
    }
    
    func handleTwoStepOrFactor(data: Data, response: URLResponse, serviceKey: String) async throws -> AuthenticationState {
        let httpResponse = response as! HTTPURLResponse
        let sessionID = (httpResponse.allHeaderFields["X-Apple-ID-Session-Id"] as! String)
        let scnt = (httpResponse.allHeaderFields["scnt"] as! String)
        
        let authOptions: AuthOptionsResponse = try await networkService.requestObject(URLRequest.authOptions(serviceKey: serviceKey, sessionID: sessionID, scnt: scnt))
        
        switch authOptions.kind {
        case .twoStep:
            throw AuthenticationError.accountUsesTwoStepAuthentication
        case .twoFactor, .securityKey:
            return self.handleTwoFactor(serviceKey: serviceKey, sessionID: sessionID, scnt: scnt, authOptions: authOptions)
        case .unknown:
            let possibleResponseString = String(data: data, encoding: .utf8)
            throw AuthenticationError.accountUsesUnknownAuthenticationKind(possibleResponseString)
        }
    }
    
    func handleTwoFactor(serviceKey: String, sessionID: String, scnt: String, authOptions: AuthOptionsResponse) -> AuthenticationState {
        let option: TwoFactorOption

        // SMS was sent automatically
        if authOptions.smsAutomaticallySent {
            option = .smsSent(authOptions.trustedPhoneNumbers!.first!)
        // SMS wasn't sent automatically because user needs to choose a phone to send to
        } else if authOptions.canFallBackToSMS {
            option = .smsPendingChoice
            // Code is shown on trusted devices
        } else if authOptions.fsaChallenge != nil {
            option = .securityKey
            // User needs to use a physical security key to respond to the challenge
        } else {
            option = .codeSent
        }
        
        let sessionData = AppleSessionData(serviceKey: serviceKey, sessionID: sessionID, scnt: scnt)
        return AuthenticationState.waitingForSecondFactor(option, authOptions, sessionData)
    }
    
    private func loadHashcash(accountName: String, serviceKey: String) async throws -> String {
        
        let result: (Data, URLResponse) = try await networkService.requestData(URLRequest.federate(account: accountName, serviceKey: serviceKey), validators: [])
        let response = result.1
        
        guard let response = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }
        
        switch response.statusCode {
        case 200..<300:
            guard let bitsString = response.allHeaderFields["X-Apple-HC-Bits"] as? String, let bits = UInt(bitsString) else {
                throw AuthenticationError.invalidHashcash
            }
            guard let challenge = response.allHeaderFields["X-Apple-HC-Challenge"] as? String else {
                throw AuthenticationError.invalidHashcash
            }
            guard let hashcash = Hashcash().mint(resource: challenge, bits: bits) else {
                throw AuthenticationError.invalidHashcash
            }
            return (hashcash)
        case 400, 401:
            throw AuthenticationError.invalidHashcash
        case let code:
            throw AuthenticationError.badStatusCode(statusCode: code, data: nil, response: response)
        }
    }

    /// Checks whether an account uses federated authentication with an existing Apple auth service key.
    ///
    /// Use ``checkIsFederated(accountName:)`` unless you have already loaded a service key as part of a
    /// custom flow.
    public func checkFederation(accountName: String, serviceKey: String) async throws -> FederationResponse {
        try await networkService.requestObject(URLRequest.checkFederation(serviceKey: serviceKey, accountName: accountName))
    }

    /// Checks whether an Apple ID is federated and, when it is, returns identity-provider details.
    public func checkIsFederated(accountName: String) async throws -> FederationResponse {
        let serviceKeyResponse: ServiceKeyResponse = try await networkService.requestObject(URLRequest.itcServiceKey)
        return try await checkFederation(accountName: accountName, serviceKey: serviceKeyResponse.authServiceKey)
    }

    /// Completes a federated sign-in after the identity provider redirects back with a token.
    ///
    /// Pass the callback values from ``FederatedAuthenticationCallback``. On success, the method persists
    /// session-only Apple cookies and validates the resulting session.
    /// - Returns: The authenticated state, or a second-factor state if Apple requires additional verification.
    @discardableResult
    public func validateFederatedToken(widgetKey: String, token: String, relayState: String) async throws -> AuthenticationState {
        let result = try await networkService.requestData(
            URLRequest.federateValidate(widgetKey: widgetKey, token: token, relayState: relayState),
            validators: []
        )

        guard let response = result.1 as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }

        switch response.statusCode {
        case 200..<300:
            persistSessionOnlyAppleCookies()
            return try await validateSession()
        case 409:
            return try await handleTwoStepOrFactor(data: result.0, response: response, serviceKey: widgetKey)
        default:
            throw AuthenticationError.unexpectedSignInResponse(statusCode: response.statusCode, message: nil)
        }
    }

    /// Completes a federated sign-in from the full callback URL.
    ///
    /// This is useful for command-line flows where a user pastes the browser URL after signing in with
    /// their organization's identity provider.
    @discardableResult
    public func validateFederatedCallbackURL(_ callbackURL: URL) async throws -> AuthenticationState {
        let callback = try FederatedAuthenticationCallback(callbackURL: callbackURL)
        return try await validateFederatedToken(
            widgetKey: callback.widgetKey,
            token: callback.token,
            relayState: callback.relayState
        )
    }

    /// Completes a federated sign-in from the callback URL string.
    ///
    /// The URL must contain `widgetKey`, `token`, and `relayState` query parameters.
    @discardableResult
    public func validateFederatedCallbackURLString(_ callbackURLString: String) async throws -> AuthenticationState {
        let callback = try FederatedAuthenticationCallback(callbackURLString: callbackURLString)
        return try await validateFederatedToken(
            widgetKey: callback.widgetKey,
            token: callback.token,
            relayState: callback.relayState
        )
    }

    /// Converts Apple session-only cookies in the client's cookie storage into persistent cookies.
    ///
    /// Some federated flows return session-only cookies. Call this if your app needs those cookies to
    /// survive beyond the current process or session configuration.
    /// - Parameter expirationDate: The expiration date assigned to converted cookies.
    public func persistSessionOnlyAppleCookies(expiring expirationDate: Date = Date(timeIntervalSinceNow: 24 * 60 * 60)) {
        let appleDomains = [".apple.com", ".idmsa.apple.com", "appstoreconnect.apple.com"]
        guard let cookieStorage = networkService.urlSession.configuration.httpCookieStorage else { return }

        for cookie in cookieStorage.cookies ?? [] where cookie.isSessionOnly {
            guard appleDomains.contains(where: { cookie.domain.hasSuffix($0) }) else { continue }

            var properties: [HTTPCookiePropertyKey: Any] = [
                .name: cookie.name,
                .value: cookie.value,
                .domain: cookie.domain,
                .path: cookie.path,
                .secure: cookie.isSecure,
                .expires: expirationDate
            ]
            if let version = cookie.properties?[.version] {
                properties[.version] = version
            }

            cookieStorage.deleteCookie(cookie)
            if let persistentCookie = HTTPCookie(properties: properties) {
                cookieStorage.setCookie(persistentCookie)
            }
        }
    }
    
    private func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
    
    private func pbkdf2(password: String, saltData: Data, keyByteCount: Int, prf: CCPseudoRandomAlgorithm, rounds: Int, protocol srpProtocol: SRPProtocol) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        let hashedPasswordDataRaw = sha256(data: passwordData)
        let hashedPasswordData = switch srpProtocol {
        case .s2k: hashedPasswordDataRaw
        // the legacy s2k_fo protocol requires hex-encoding the digest before performing PBKDF2.
        case .s2k_fo: Data(hashedPasswordDataRaw.hexEncodedString().lowercased().utf8)
        }

        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        let derivedCount = derivedKeyData.count
        let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            let keyBuffer: UnsafeMutablePointer<UInt8> =
                derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return saltData.withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return hashedPasswordData.withUnsafeBytes { hashedPasswordBytes -> Int32 in
                    let passwordBuffer: UnsafePointer<UInt8> = hashedPasswordBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer,
                        hashedPasswordData.count,
                        saltBuffer,
                        saltData.count,
                        prf,
                        UInt32(rounds),
                        keyBuffer,
                        derivedCount)
                }
            }
        }
        return derivationStatus == kCCSuccess ? derivedKeyData : nil
    }
    
    // MARK: MFA
    
    /// Requests that Apple send an SMS security code to a trusted phone number.
    ///
    /// Call this after receiving `.waitingForSecondFactor(.smsPendingChoice, authOptions, sessionData)`.
    /// - Returns: `.waitingForSecondFactor(.smsSent, authOptions, sessionData)`.
    public func requestSMSSecurityCode(to trustedPhoneNumber: AuthOptionsResponse.TrustedPhoneNumber, authOptions: AuthOptionsResponse, sessionData: AppleSessionData) async throws -> AuthenticationState {
        
        try await networkService.requestVoid(URLRequest.requestSecurityCode(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt, trustedPhoneID: trustedPhoneNumber.id))
        
        return AuthenticationState.waitingForSecondFactor(.smsSent(trustedPhoneNumber), authOptions, sessionData)
    }
    
    /// Submits a trusted-device or SMS verification code to complete two-factor authentication.
    /// - Parameters:
    ///   - code: The verification code and its delivery channel.
    ///   - sessionData: The session headers returned in the second-factor authentication state.
    /// - Returns: The authenticated state after Apple trusts and validates the session.
    public func submitSecurityCode(_ code: SecurityCode, sessionData: AppleSessionData) async throws -> AuthenticationState {
        let result: (Data, URLResponse) = try await networkService.requestData(URLRequest.submitSecurityCode(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt, code: code), validators: [])
        let response = result.1
        
        guard let response = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }
        let data = result.0
        
        switch response.statusCode {
        case 200..<300:
            return try await updateSession(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt)
        case 400, 401:
            throw AuthenticationError.incorrectSecurityCode
        case 412:
            throw AuthenticationError.appleIDAndPrivacyAcknowledgementRequired
        case let code:
            throw AuthenticationError.badStatusCode(statusCode: code, data: data, response: response)
        }
    }
    
    /// Submits a serialized FSA/security-key challenge response.
    ///
    /// Apps using the `XcodesLoginKitSecurityKey` product should usually call
    /// `submitSecurityKeyPinCode(_:sessionData:authOptions:)` instead.
    public func submitChallenge(response: Data, sessionData: AppleSessionData) async throws -> AuthenticationState {
        
        let result: (Data, URLResponse) = try await networkService.requestData(URLRequest.respondToChallenge(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt, response: response), validators: [])
        let response = result.1
        
        guard let response = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }
        let data = result.0
        
        switch response.statusCode {
        case 200..<300:
            return try await updateSession(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt)
        case 400, 401:
            throw AuthenticationError.incorrectSecurityCode
        case 412:
            throw AuthenticationError.appleIDAndPrivacyAcknowledgementRequired
        case let code:
            throw AuthenticationError.badStatusCode(statusCode: code, data: data, response: response)
        }
    }
    
    func updateSession(serviceKey: String, sessionID: String, scnt: String) async throws -> AuthenticationState {
        try await networkService.requestVoid(URLRequest.trust(serviceKey: serviceKey, sessionID: sessionID, scnt: scnt))
        return try await validateSession()
    }
    
    /// Validates the current cookies and returns the authenticated Apple session.
    ///
    /// Call this after importing cookies or when your app starts to check whether the stored session is
    /// still accepted by Apple.
    public func validateSession() async throws -> AuthenticationState {
        let authenticationSession: AppleSession = try await networkService.requestObject(URLRequest.olympusSession)
        return AuthenticationState.authenticated(authenticationSession)
    }
}

extension Client {
    /// Clears all cookies from the client's URL session.
    public func signout() {
        networkService.urlSession.configuration.httpCookieStorage?.removeCookies(since: .distantPast)
    }
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
