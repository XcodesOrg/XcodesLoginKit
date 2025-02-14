//
//  SignInPhoneListView.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-02-13.
//

import SwiftUI
import XcodesLoginKit

struct SignInPhoneListView: View {
    @Environment(AppState.self) private var appState
    @Binding var isPresented: Bool
    @State private var selectedPhoneNumberID: AuthOptionsResponse.TrustedPhoneNumber.ID?
    
    let authOptions: AuthOptionsResponse
    let sessionData: AppleSessionData

    var body: some View {
        VStack(alignment: .leading) {
            if let phoneNumbers = authOptions.trustedPhoneNumbers, !phoneNumbers.isEmpty {
                Text(String(format: "Select a trusted phone number to receive a %d digit code via SMS:", authOptions.securityCode!.length))

                List(phoneNumbers, selection: $selectedPhoneNumberID) {
                    Text($0.numberWithDialCode)
                }
                .onAppear {
                    if phoneNumbers.count == 1 {
                        selectedPhoneNumberID = phoneNumbers.first?.id
                    }
                }
            } else {
                Text("NoTrustedPhones")
                    .font(.callout)
                Spacer()
            }

            HStack {
                Button("Cancel", action: { isPresented = false })
                    .keyboardShortcut(.cancelAction)
                Spacer()
                ProgressButton(isInProgress: appState.isProcessingAuthRequest,
                               action: { appState.requestSMS(to: authOptions.trustedPhoneNumbers!.first { $0.id == selectedPhoneNumberID }!, authOptions: authOptions, sessionData: sessionData) })
                {
                    Text("Continue")
                }
                .keyboardShortcut(.defaultAction)
                .disabled(selectedPhoneNumberID == nil)
            }
            .frame(height: 25)
        }
        .padding()
        .frame(width: 400, height: 200)
    }
}
