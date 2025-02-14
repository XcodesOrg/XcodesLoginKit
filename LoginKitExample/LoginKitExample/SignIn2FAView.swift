//
//  SignIn2FAView.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-02-03.
//


import SwiftUI
import XcodesLoginKit

struct SignIn2FAView: View {
    @Environment(AppState.self) var appState
    
    @Binding var isPresented: Bool
    @State private var code: String = ""
    let authOptions: AuthOptionsResponse
    let sessionData: AppleSessionData
    
    var body: some View {
        VStack(alignment: .leading) {
            Text(String(format: "Enter the %d digit code from one of your trusted devices:", authOptions.securityCode!.length))
                .fixedSize(horizontal: true, vertical: false)
            
            HStack {
                Spacer()
                PinCodeTextField(code: $code, numberOfDigits: authOptions.securityCode!.length) {
                    appState.submitSecurityCode(SecurityCode.device(code: $0), sessionData: sessionData)
                }
                Spacer()
            }
            .padding()
            
            HStack {
                Button("Cancel", action: { isPresented = false })
                    .keyboardShortcut(.cancelAction)
                Button("SendSMS", action: { appState.choosePhoneNumberForSMS(authOptions: authOptions, sessionData: sessionData) })
                Spacer()
                ProgressButton(isInProgress: appState.isProcessingAuthRequest,
                               action: { appState.submitSecurityCode(.device(code: code), sessionData: sessionData) }) {
                    Text("Continue")
                }
                .keyboardShortcut(.defaultAction)
                .disabled(code.count != authOptions.securityCode!.length)
            }
            .frame(height: 25)
        }
        .padding()
        
    }
}
