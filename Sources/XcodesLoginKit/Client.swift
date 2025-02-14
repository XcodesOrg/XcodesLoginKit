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
import LibFido2Swift

public class Client {
    private static let authTypes = ["sa", "hsa", "non-sa", "hsa2"]

    /// Security key client. Hold reference for cancelling if needed
    private var fido2: FIDO2?
    
    public init() {}
    
    
    // MARK: Login
    
    @MainActor
    public func srpLogin(accountName: String, password: String) async throws -> AuthenticationState {
        let client = SRPClient(configuration: SRPConfiguration<SHA256>(.N2048))
        let clientKeys = client.generateKeys()
        let a = clientKeys.public
        
        
        let serviceKeyResponse: ServiceKeyResponse = try await Current.network.networkService.requestObject(URLRequest.itcServiceKey)
        let serviceKey = serviceKeyResponse.authServiceKey
        
        // Fixes issue https://github.com/RobotsAndPencils/XcodesApp/issues/360
        // On 2023-02-23, Apple added a custom implementation of hashcash to their auth flow
        // Without this addition, Apple ID's would get set to locked
        let hashcash = try await loadHashcash(accountName: accountName, serviceKey: serviceKey)
        
        let srp: ServerSRPInitResponse = try await Current.network.networkService.requestObject(URLRequest.SRPInit(serviceKey: serviceKey, a: Data(a.bytes).base64EncodedString(), accountName: accountName))
        
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

        let result: (Data, URLResponse) = try await Current.network.networkService.requestData(URLRequest.SRPComplete(serviceKey: serviceKey, hashcash: hashcash, accountName: accountName, c: srp.c, m1: Data(m1).base64EncodedString(), m2: Data(m2).base64EncodedString()), validators: [])
        
        guard let httpResponse = result.1 as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }
        guard let data = result.0 as? Data else {
            throw NetworkError.invalidResponseFormat
        }
        
        var responseBody: SignInResponse
        do {
            responseBody = try JSONDecoder.networkJSONDecoder.decode(SignInResponse.self, from: data)
        } catch {
            throw NetworkError.decoding(error: error)
        }
        
        
        switch httpResponse.statusCode {
        case 200:
            let authenticationSession: AppleSession = try await Current.network.networkService.requestObject(URLRequest.olympusSession)
            return AuthenticationState.authenticated(authenticationSession)
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
        
        return AuthenticationState.unauthenticated
    }
    
    @MainActor
    func handleTwoStepOrFactor(data: Data, response: URLResponse, serviceKey: String) async throws -> AuthenticationState {
        let httpResponse = response as! HTTPURLResponse
        let sessionID = (httpResponse.allHeaderFields["X-Apple-ID-Session-Id"] as! String)
        let scnt = (httpResponse.allHeaderFields["scnt"] as! String)
        
        let authOptions: AuthOptionsResponse = try await Current.network.networkService.requestObject(URLRequest.authOptions(serviceKey: serviceKey, sessionID: sessionID, scnt: scnt))
        
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
    
    @MainActor
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
    
    @MainActor
    private func loadHashcash(accountName: String, serviceKey: String) async throws -> String {
        
        let result: (Data, URLResponse) = try await Current.network.networkService.requestData(URLRequest.federate(account: accountName, serviceKey: serviceKey), validators: [])
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
    
    /// User has chosen to send an SMS to a particular trusted phone number
    /// - Returns: AuthenticationState.waitingForSecondFactor
    public func requestSMSSecurityCode(to trustedPhoneNumber: AuthOptionsResponse.TrustedPhoneNumber, authOptions: AuthOptionsResponse, sessionData: AppleSessionData) async throws -> AuthenticationState {
        
        let result = try await Current.network.networkService.requestVoid(URLRequest.requestSecurityCode(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt, trustedPhoneID: trustedPhoneNumber.id))
        
        return AuthenticationState.waitingForSecondFactor(.smsSent(trustedPhoneNumber), authOptions, sessionData)
    }
    
    public func submitSecurityCode(_ code: SecurityCode, sessionData: AppleSessionData) async throws ->AuthenticationState {
        let result: (Data, URLResponse) = try await Current.network.networkService.requestData(URLRequest.submitSecurityCode(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt, code: code), validators: [])
        let response = result.1
        
        guard let response = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }
        guard let data = result.0 as? Data else {
            throw NetworkError.invalidResponseFormat
        }
        
        switch response.statusCode {
        case 200..<300:
            return await try updateSession(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt)
        case 400, 401:
            throw AuthenticationError.incorrectSecurityCode
        case 412:
            throw AuthenticationError.appleIDAndPrivacyAcknowledgementRequired
        case let code:
            throw AuthenticationError.badStatusCode(statusCode: code, data: data, response: response)
        }
    }
    
    public func submitChallenge(response: Data, sessionData: AppleSessionData) async throws -> AuthenticationState {
        
        let result: (Data, URLResponse) = try await Current.network.networkService.requestData(URLRequest.respondToChallenge(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt, response: response), validators: [])
        let response = result.1
        
        guard let response = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponseFormat
        }
        guard let data = result.0 as? Data else {
            throw NetworkError.invalidResponseFormat
        }
        
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
        try await Current.network.networkService.requestVoid(URLRequest.trust(serviceKey: serviceKey, sessionID: sessionID, scnt: scnt))
        return try await loadSession()
    }
    
    func loadSession() async throws -> AuthenticationState {
        let authenticationSession: AppleSession = try await Current.network.networkService.requestObject(URLRequest.olympusSession)
        return AuthenticationState.authenticated(authenticationSession)
    }
}

// MARK: Security Key Authentication
extension Client {
    public func submitSecurityKeyPinCode(_ pinCode: String, sessionData: AppleSessionData, authOptions: AuthOptionsResponse) async throws -> AuthenticationState {
        guard let fsaChallenge = authOptions.fsaChallenge else {
            throw AuthenticationError.unexpectedSignInResponse(statusCode: 0, message: "Auth response is not a FSA Challenge type. Security not secure key?")
        }
        
        // The challenge is encoded in Base64URL encoding
        let challengeUrl = fsaChallenge.challenge
        let challenge = FIDO2.base64urlToBase64(base64url: challengeUrl)
        let origin = "https://idmsa.apple.com"
        let rpId = "apple.com"
        // Allowed creds is sent as a comma separated string
        let validCreds = fsaChallenge.allowedCredentials.split(separator: ",").map(String.init)

        do {
            let fido2 = FIDO2()
            self.fido2 = fido2
            let response = try fido2.respondToChallenge(args: ChallengeArgs(rpId: rpId, validCredentials: validCreds, devPin: pinCode, challenge: challenge, origin: origin))
        
            let respData = try JSONEncoder().encode(response)
            
            return try await submitChallenge(response: respData, sessionData: AppleSessionData(serviceKey: sessionData.serviceKey, sessionID: sessionData.sessionID, scnt: sessionData.scnt))
            
        } catch FIDO2Error.canceledByUser {
            // User cancelled the auth flow
            throw AuthenticationError.userCancelledSecurityKeyAuthentication
        } catch {
            throw error
        }
    }
    
    public func cancelSecurityKeyAssertationRequest() {
        self.fido2?.cancel()
    }
    
    /// Clears any cookies from URLSession
    @MainActor
    public func signout() {
        Current.network.session.configuration.httpCookieStorage?.removeCookies(since: .distantPast)
    }
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
