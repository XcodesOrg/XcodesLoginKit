//
//  SignInSecurityKeyPinView.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-02-13.
//

import SwiftUI
import XcodesLoginKit

struct SignInSecurityKeyPinView: View {
    @Environment(AppState.self) private var appState
    @Binding var isPresented: Bool
    @State private var pin: String = ""
    
    let authOptions: AuthOptionsResponse
    let sessionData: AppleSessionData
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Insert your physical security key and enter the PIN")
                .fixedSize(horizontal: true, vertical: false)
            
            HStack {
                Spacer()
                SecureField("PIN", text: $pin)
                Spacer()
            }
            .padding()
            
            HStack {
                Button("Cancel", action: { isPresented = false })
                    .keyboardShortcut(.cancelAction)
                Spacer()
                ProgressButton(isInProgress: appState.isProcessingAuthRequest,
                               action: submitPinCode) {
                    Text("Continue")
                }
                .keyboardShortcut(.defaultAction)
                // FIDO2 device pin codes must be at least 4 code points
                // https://docs.yubico.com/yesdk/users-manual/application-fido2/fido2-pin.html
                .disabled(pin.count < 4)
            }
            .frame(height: 25)
        }
        .padding()
    }
    
    func submitPinCode() {
        appState.createAndSubmitSecurityKeyAssertationWithPinCode(pin, sessionData: sessionData, authOptions: authOptions)
    }
}
