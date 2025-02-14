//
//  SignInSMSView.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-02-13.
//

import SwiftUI
import XcodesLoginKit

struct SignInSMSView: View {
    @Environment(AppState.self) private var appState
    
    @Binding var isPresented: Bool
    @State private var code: String = ""
    
    let trustedPhoneNumber: AuthOptionsResponse.TrustedPhoneNumber
    let authOptions: AuthOptionsResponse
    let sessionData: AppleSessionData

    var body: some View {
        VStack(alignment: .leading) {
            Text(String(format: "Enter the %1$d digit code sent to %2$@: ", authOptions.securityCode!.length, trustedPhoneNumber.numberWithDialCode))
            
            HStack {
                Spacer()
                PinCodeTextField(code: $code, numberOfDigits: authOptions.securityCode!.length) {
                    appState.submitSecurityCode(.sms(code: $0, phoneNumberId: trustedPhoneNumber.id), sessionData: sessionData)
                }
                Spacer()
            }
            .padding()
            
            HStack {
                Button("Cancel", action: { isPresented = false })
                    .keyboardShortcut(.cancelAction)
                Spacer()
                ProgressButton(isInProgress: appState.isProcessingAuthRequest,
                               action: { appState.submitSecurityCode(.sms(code: code, phoneNumberId: trustedPhoneNumber.id), sessionData: sessionData) }) {
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
