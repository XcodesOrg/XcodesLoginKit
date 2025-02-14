//
//  AuthenticationError.swift
//  XcodesLoginKit
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import Foundation

public enum AuthenticationError: Swift.Error, LocalizedError, Equatable {
    case invalidSession
    case invalidHashcash
    case invalidUsernameOrPassword(username: String)
    case incorrectSecurityCode
    case unexpectedSignInResponse(statusCode: Int, message: String?)
    case appleIDAndPrivacyAcknowledgementRequired
    case accountUsesTwoStepAuthentication
    case accountUsesUnknownAuthenticationKind(String?)
    case accountLocked(String)
    case badStatusCode(statusCode: Int, data: Data?, response: HTTPURLResponse)
    case notDeveloperAppleId
    case notAuthorized
    case invalidResult(resultString: String?)
    case srpInvalidPublicKey
    case userCancelledSecurityKeyAuthentication
    
    public var errorDescription: String? {
        switch self {
        case .invalidSession:
            return "Your authentication session is invalid. Try signing in again."
        case .invalidHashcash:
            return "Could not create a hashcash for the session."
        case .invalidUsernameOrPassword:
            return "Invalid username and password combination."
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
        }
    }
}
