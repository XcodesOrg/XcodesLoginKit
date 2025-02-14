//
//  ProgressButton.swift
//  LoginKitExample
//
//  Created by Matt Kiazyk on 2025-01-31.
//

import SwiftUI

struct ProgressButton<Label: View>: View {
    let isInProgress: Bool
    let action: () -> Void
    let label: () -> Label

    init(isInProgress: Bool, action: @escaping () -> Void, @ViewBuilder label: @escaping () -> Label) {
        self.isInProgress = isInProgress
        self.action = action
        self.label = label
    }

    var body: some View {
        Button(action: action) {
            // This might look like a strange way to switch between the label and the progress view.
            // Doing it this way, so that the label is hidden but still has the same frame and is in the view hierarchy
            // makes sure that the button's frame doesn't change when isInProgress changes.
            label()
                .isHidden(isInProgress)
                .overlay(
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .scaleEffect(x: 0.5, y: 0.5, anchor: .center)
                        .isHidden(!isInProgress)
                )
        }
        .disabled(isInProgress)
    }
}

extension View {
    @ViewBuilder
    func isHidden(_ isHidden: Bool) -> some View {
        if isHidden {
            self.hidden()
        } else {
            self
        }
    }
}
