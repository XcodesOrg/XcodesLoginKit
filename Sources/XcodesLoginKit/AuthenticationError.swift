//
//  AuthenticationError.swift
//  XcodesLoginKit
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import Foundation

/// Errors returned by XcodesLoginKit's Apple authentication flow.
public enum AuthenticationError: Swift.Error, LocalizedError, Equatable, Sendable {
    /// The current cookies do not represent a valid Apple session.
    case invalidSession
    /// Apple's hashcash challenge could not be solved or parsed.
    case invalidHashcash
    /// Apple rejected the username and password combination.
    case invalidUsernameOrPassword(username: String)
    /// Apple rejected the submitted two-factor verification code.
    case incorrectSecurityCode
    /// Apple returned a sign-in response that XcodesLoginKit does not recognize.
    case unexpectedSignInResponse(statusCode: Int, message: String?)
    /// The Apple ID & Privacy agreement must be acknowledged in App Store Connect.
    case appleIDAndPrivacyAcknowledgementRequired
    /// The account uses legacy two-step authentication, which is not supported.
    case accountUsesTwoStepAuthentication
    /// Apple reported an authentication kind that XcodesLoginKit cannot classify.
    case accountUsesUnknownAuthenticationKind(String?)
    /// Apple reports that the account is locked.
    case accountLocked(String)
    /// Apple returned an unexpected HTTP status code.
    case badStatusCode(statusCode: Int, data: Data?, response: HTTPURLResponse)
    /// The Apple ID is not registered as an Apple Developer.
    case notDeveloperAppleId
    /// The current session is not authorized for the requested operation.
    case notAuthorized
    /// Apple returned an invalid or unexpected result payload.
    case invalidResult(resultString: String?)
    /// The SRP public key or salt returned by Apple could not be decoded.
    case srpInvalidPublicKey
    /// The user cancelled security-key authentication.
    case userCancelledSecurityKeyAuthentication
    /// The account requires federated authentication via a browser.
    case federatedAuthenticationRequired
    /// The federated callback URL did not include the required query parameters.
    case invalidFederatedAuthenticationCallback
    /// A password is required because the account is not federated.
    case missingPasswordForNonFederatedAccount
    /// None of Apple's available sign-in service-key sources returned a usable key.
    case serviceKeyResolutionFailed(attempts: [AppleServiceKeyAttempt])
    
    /// A user-visible error description.
    public var errorDescription: String? {
        switch self {
        case .invalidSession:
            return "Your authentication session is invalid. Try signing in again."
        case .invalidHashcash:
            return "Could not create a hashcash for the session."
        case let .invalidUsernameOrPassword(username):
            return "Invalid username and password combination. Attempted to sign in with username \(username)."
        case .incorrectSecurityCode:
            return "The code that was entered is incorrect."
        case let .unexpectedSignInResponse(statusCode, message):
            return """
                Received an unexpected sign in response. If you continue to have problems, please submit a bug report in the Help menu and include the following information:

                Status code: \(statusCode)
                \(message != nil ? ("Message: " + message!) : "")
                """
        case .appleIDAndPrivacyAcknowledgementRequired:
            return "You must sign in to https://appstoreconnect.apple.com and acknowledge the Apple ID & Privacy agreement."
        case .accountUsesTwoStepAuthentication:
            return "Received a response from Apple that indicates this account has two-step authentication enabled. xcodes currently only supports the newer two-factor authentication, though. Please consider upgrading to two-factor authentication, or explain why this isn't an option for you by making a new feature request in the Help menu."
        case .accountUsesUnknownAuthenticationKind:
            return "Received a response from Apple that indicates this account has two-step or two-factor authentication enabled, but xcodes is unsure how to handle this response. If you continue to have problems, please submit a bug report in the Help menu."
        case let .accountLocked(message):
            return message
        case let .badStatusCode(statusCode, _, _):
            return "Received an unexpected status code: \(statusCode). If you continue to have problems, please submit a bug report in the Help menu."
        case .notDeveloperAppleId:
            return "You are not registered as an Apple Developer.  Please visit Apple Developer Registration. https://developer.apple.com/register/"
        case .notAuthorized:
            return "You are not authorized. Please Sign in with your Apple ID first."
        case let .invalidResult(resultString):
            return resultString ?? "If you continue to have problems, please submit a bug report in the Help menu."
        case .srpInvalidPublicKey:
            return "Invalid Key"
        case .userCancelledSecurityKeyAuthentication:
            return "User cancelled security key authorization"
        case .federatedAuthenticationRequired:
            return "This account uses federated authentication. Browser-based sign in is required."
        case .invalidFederatedAuthenticationCallback:
            return "The federated authentication callback URL is missing required parameters."
        case .missingPasswordForNonFederatedAccount:
            return "This Apple ID does not use federated authentication. Enter your password to continue."
        case let .serviceKeyResolutionFailed(attempts):
            let details = attempts
                .map { "\($0.source.displayName): \($0.failure.displayName)" }
                .joined(separator: "; ")
            return "Could not retrieve Apple's sign-in service key. \(details)"
        }
    }
}

private extension AppleServiceKeySource {
    var displayName: String {
        switch self {
        case .supplied:
            return "Supplied key"
        case .cache:
            return "Cached key"
        case .appStoreConnectSignOut:
            return "App Store Connect sign-out redirect"
        case .olympus:
            return "App Store Connect Olympus endpoint"
        }
    }
}

private extension AppleServiceKeyFailure {
    var displayName: String {
        switch self {
        case let .network(description):
            return "network request failed (\(description))"
        case .invalidResponse:
            return "returned a non-HTTP response"
        case let .httpStatus(code, bodyPreview):
            if let bodyPreview {
                return "returned HTTP \(code) (\(bodyPreview))"
            }
            return "returned HTTP \(code)"
        case .missingRedirect:
            return "did not return a Location header"
        case .invalidRedirect:
            return "returned an invalid Location header"
        case .missingKey:
            return "did not contain a service key"
        }
    }
}
