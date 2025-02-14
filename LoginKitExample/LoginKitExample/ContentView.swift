//
//  ContentView.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import SwiftUI

struct ContentView: View {
    private enum FocusedField {
        case username, password
    }
    
    @Environment(AppState.self) var appState
    
    @State private var username: String = ""
    @State private var password: String = ""
    @FocusState private var focusedField: FocusedField?
    
    var body: some View {
        @Bindable var appState = appState
        
        VStack(alignment: .leading) {
            Text("SignInWithApple")
                .bold()
                .padding(.vertical)
            HStack {
                Text("AppleID")
                    .frame(minWidth: 100, alignment: .trailing)
                TextField(text: $username) {
                    Text(verbatim: "example@icloud.com")
                }
                .focused($focusedField, equals: .username)
            }
            HStack {
                Text("Password")
                    .frame(minWidth: 100, alignment: .trailing)
                SecureField("Required", text: $password)
                    .focused($focusedField, equals: .password)
            }
            if appState.authError != nil {
                HStack {
                    Text("")
                        .frame(minWidth: 100)
                    Text(appState.authError?.localizedDescription ?? "")
                        .fixedSize(horizontal: false, vertical: true)
                        .foregroundColor(.red)
                }
            }
            
            HStack {
                Spacer()
                Button("Cancel") {
                    appState.authError = nil
                }
                    .keyboardShortcut(.cancelAction)
                ProgressButton(
                    isInProgress: appState.isProcessingAuthRequest,
                    action: { appState.signIn(username: username, password: password) },
                    label: {
                        Text("Next")
                    }
                )
                .disabled(username.isEmpty || password.isEmpty)
                .keyboardShortcut(.defaultAction)
            }
            .frame(height: 25)
        }
        .padding()
        .sheet(item: $appState.presentedSheet) { sheet in
            switch sheet {
            case .twoFactor(let secondFactorData):
                secondFactorView(secondFactorData)
                    .environment(appState)
            case .securityKeyTouchToConfirm:
                
                SignInSecurityKeyTouchView(isPresented: $appState.presentedSheet.isNotNil)
                    .environment(appState)
            }
        }
    }
    
    @ViewBuilder
    private func secondFactorView(_ secondFactorData: XcodesSheet.SecondFactorData) -> some View {
        @Bindable var appState = appState
        
        switch secondFactorData.option {
        case .codeSent:
            SignIn2FAView(isPresented: $appState.presentedSheet.isNotNil, authOptions: secondFactorData.authOptions, sessionData: secondFactorData.sessionData)
        case .smsSent(let trustedPhoneNumber):
            SignInSMSView(isPresented: $appState.presentedSheet.isNotNil, trustedPhoneNumber: trustedPhoneNumber, authOptions: secondFactorData.authOptions, sessionData: secondFactorData.sessionData)
        case .smsPendingChoice:
            SignInPhoneListView(isPresented: $appState.presentedSheet.isNotNil, authOptions: secondFactorData.authOptions, sessionData: secondFactorData.sessionData)
        case .securityKey:
            SignInSecurityKeyPinView(isPresented: $appState.presentedSheet.isNotNil, authOptions: secondFactorData.authOptions, sessionData: secondFactorData.sessionData)
        }
    }
}

#Preview {
    ContentView()
}
