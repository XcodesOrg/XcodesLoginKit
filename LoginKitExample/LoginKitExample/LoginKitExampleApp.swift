//
//  LoginKitExampleApp.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import SwiftUI

@main
struct LoginKitExampleApp: App {
    @State private var appState = AppState()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(appState)
        }
    }
}
