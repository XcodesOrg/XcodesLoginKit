import Foundation
import LibFido2Swift
import XcodesLoginKit

private final class SecurityKeyStore: @unchecked Sendable {
    private let lock = NSLock()
    private var clients: [ObjectIdentifier: FIDO2] = [:]

    func withFIDO2<Value>(for client: Client, _ operation: (FIDO2) throws -> Value) rethrows -> Value {
        try lock.withLock {
            let identifier = ObjectIdentifier(client)
            let fido2 = clients[identifier] ?? FIDO2()
            clients[identifier] = fido2
            return try operation(fido2)
        }
    }

    func cancel(for client: Client) {
        withFIDO2(for: client) {
            $0.cancel()
        }
    }
}

private let securityKeyStore = SecurityKeyStore()

// MARK: Security Key Authentication
extension Client {
    /// Completes a security-key second-factor challenge using an attached FIDO2 device.
    ///
    /// Call this after receiving `.waitingForSecondFactor(.securityKey, authOptions, sessionData)` from
    /// the base `XcodesLoginKit` product. The optional PIN is passed to the attached security key when
    /// the device requires one.
    /// - Returns: The authenticated state after Apple accepts the security-key assertion.
    public func submitSecurityKeyPinCode(_ pinCode: String?, sessionData: AppleSessionData, authOptions: AuthOptionsResponse) async throws -> AuthenticationState {
        guard let fsaChallenge = authOptions.fsaChallenge else {
            throw AuthenticationError.unexpectedSignInResponse(statusCode: 0, message: "Auth response is not a FSA Challenge type. Security not secure key?")
        }

        let challenge = FIDO2.base64urlToBase64(base64url: fsaChallenge.challenge)
        let validCreds = fsaChallenge.allowedCredentials.split(separator: ",").map(String.init)

        do {
            let response = try securityKeyStore.withFIDO2(for: self) { fido2 in
                try fido2.respondToChallenge(args: ChallengeArgs(
                    rpId: "apple.com",
                    validCredentials: validCreds,
                    devPin: pinCode,
                    challenge: challenge,
                    origin: "https://idmsa.apple.com"
                ))
            }
            let responseData = try JSONEncoder().encode(response)

            return try await submitChallenge(response: responseData, sessionData: AppleSessionData(
                serviceKey: sessionData.serviceKey,
                sessionID: sessionData.sessionID,
                scnt: sessionData.scnt
            ))
        } catch FIDO2Error.canceledByUser {
            throw AuthenticationError.userCancelledSecurityKeyAuthentication
        } catch {
            throw error
        }
    }

    /// Returns whether a supported security-key device is currently attached.
    public func hasSecurityKeyDeviceAttached() -> Bool {
        securityKeyStore.withFIDO2(for: self) {
            $0.hasDeviceAttached()
        }
    }

    /// Returns whether the attached security key requires a PIN before assertion.
    public func securityKeyDeviceNeedsPin() throws -> Bool {
        try securityKeyStore.withFIDO2(for: self) {
            try $0.deviceHasPin()
        }
    }

    /// Cancels an in-progress security-key assertion request for this client.
    public func cancelSecurityKeyAssertationRequest() {
        securityKeyStore.cancel(for: self)
    }
}
