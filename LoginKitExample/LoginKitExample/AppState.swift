//
//  AppState.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import Foundation
import XcodesLoginKit
import SwiftUI

@Observable
class AppState {
    var authError: Error?
    var isProcessingAuthRequest = false
    var presentedSheet: XcodesSheet? = nil
    
    @MainActor
    private let client = Client()
    
    func signIn(username: String, password: String) {
        isProcessingAuthRequest = true
        
        Task {
            do {
                let autheticationState = try await client.srpLogin(accountName: username, password: password)
                handleAuthenticationFlowCompletion(autheticationState)
                isProcessingAuthRequest = false
            }
            catch {
                print("ERROR LOGGING IN: \(error)")
                authError = error
                isProcessingAuthRequest = false
            }
        }
    }
    
    private func handleAuthenticationFlowCompletion(_ authenticationState: AuthenticationState) {
        switch authenticationState {
        case .unauthenticated:
            authError = AuthenticationError.notAuthorized
        case let .waitingForSecondFactor(twoFactorOption, authOptionsResponse, appleSessionData):
            self.presentedSheet = .twoFactor(.init(
                option: twoFactorOption,
                authOptions: authOptionsResponse,
                sessionData: AppleSessionData(serviceKey: appleSessionData.serviceKey, sessionID: appleSessionData.sessionID, scnt: appleSessionData.scnt)
            ))
        case .authenticated(let appleSession):
            print("SUCCESSFULLY LOGGED IN - WELCOME: \(appleSession.user.fullName)")
            self.presentedSheet = nil
            break
        case .notAppleDeveloper:
            authError = AuthenticationError.notDeveloperAppleId
        }
    }
    
    
    @MainActor
    func submitSecurityCode(_ code: SecurityCode, sessionData: AppleSessionData) {
        isProcessingAuthRequest = true
        
        Task {
            do {
                let authenticationState = try await client.submitSecurityCode(code, sessionData: sessionData)
                self.handleAuthenticationFlowCompletion(authenticationState)
                self.isProcessingAuthRequest = false
            } catch {
                print("ERROR SUBMITTING SECURITYCODE: \(error)")
                authError = error
                self.isProcessingAuthRequest = false
            }
            
        }
    }
    
    func choosePhoneNumberForSMS(authOptions: AuthOptionsResponse, sessionData: AppleSessionData) {
        self.presentedSheet = .twoFactor(.init(
            option: .smsPendingChoice,
            authOptions: authOptions,
            sessionData: sessionData
        ))
    }
    
    func requestSMS(to trustedPhoneNumber: AuthOptionsResponse.TrustedPhoneNumber, authOptions: AuthOptionsResponse, sessionData: AppleSessionData) {
        isProcessingAuthRequest = true
        Task {
            do {
                let authenticationState = try await client.requestSMSSecurityCode(to: trustedPhoneNumber, authOptions: authOptions, sessionData: sessionData)
                self.handleAuthenticationFlowCompletion(authenticationState)
                self.isProcessingAuthRequest = false
                
            } catch {
                print("ERROR Requesting SMS: \(error)")
                authError = error
                self.isProcessingAuthRequest = false
            }
        }
    }
    
    func createAndSubmitSecurityKeyAssertationWithPinCode(_ pinCode: String, sessionData: AppleSessionData, authOptions: AuthOptionsResponse) {
        isProcessingAuthRequest = true
        Task {
            do {
                let authenticationState = try await client.submitSecurityKeyPinCode(pinCode, sessionData: sessionData, authOptions: authOptions)
                self.handleAuthenticationFlowCompletion(authenticationState)
                self.isProcessingAuthRequest = false
                
            } catch {
                print("ERROR Requesting SMS: \(error)")
                authError = error
                self.isProcessingAuthRequest = false
            }
        }
    }
    
    func cancelSecurityKeyAssertationRequest() {
        Task {
            await client.cancelSecurityKeyAssertationRequest()
        }
    }
}
enum XcodesSheet: Identifiable {
    case twoFactor(SecondFactorData)
    case securityKeyTouchToConfirm

    var id: Int { Kind(self).hashValue }

    struct SecondFactorData {
        let option: TwoFactorOption
        let authOptions: AuthOptionsResponse
        let sessionData: AppleSessionData
    }
    
    private enum Kind: Hashable {
        case signIn, twoFactor(TwoFactorOption), securityKeyTouchToConfirm

        enum TwoFactorOption {
            case smsSent
            case codeSent
            case smsPendingChoice
            case securityKeyPin
        }

        init(_ sheet: XcodesSheet) {
            switch sheet {
            case .twoFactor(let data):
                switch data.option {
                case .smsSent: self = .twoFactor(.smsSent)
                case .smsPendingChoice: self = .twoFactor(.smsPendingChoice)
                case .codeSent: self = .twoFactor(.codeSent)
                case .securityKey: self = .twoFactor(.securityKeyPin)
                }
            case .securityKeyTouchToConfirm: self = .securityKeyTouchToConfirm
            }
        }
    }
}

extension Optional {
    public var isNotNil: Bool {
        get { self != nil }
        set { self = newValue ? self : nil }
    }
}
