## XcodesLoginKit

A Swift API for signing in to Apple's developer services.

XcodesLoginKit handles Apple's SRP password login, federated Apple IDs, two-factor
authentication, session validation, logout, and optional fastlane/Spaceship cookie import.

### Getting started

Add the package to your `Package.swift`:

```swift
.package(url: "https://github.com/XcodesOrg/XcodesLoginKit", branch: "main")
```

Then add the product you need:

```swift
.product(name: "XcodesLoginKit", package: "XcodesLoginKit")
```

Use `Client` when your app wants to drive its own sign-in UI:

```swift
import Foundation
import XcodesLoginKit

let client = Client()

let state = try await client.authenticationState(
    accountName: "name@example.com",
    password: password
)

switch state {
case .authenticated(let session):
    print("Signed in as \(session.user.fullName ?? "Apple Developer")")

case .waitingForFederatedAuthentication(let federation):
    guard let idpURL = federation.idpURL else {
        throw AuthenticationError.federatedAuthenticationRequired
    }

    // Open idpURL in a browser. After the user signs in, collect the redirected URL.
    let callbackURLString = "... pasted or received callback URL ..."
    try await client.validateFederatedCallbackURLString(callbackURLString)

case .waitingForSecondFactor(let option, let authOptions, let sessionData):
    switch option {
    case .codeSent:
        let code = "... code from trusted device ..."
        try await client.submitSecurityCode(.device(code: code), sessionData: sessionData)

    case .smsPendingChoice:
        guard let phoneNumber = authOptions.trustedPhoneNumbers?.first else { return }
        try await client.requestSMSSecurityCode(
            to: phoneNumber,
            authOptions: authOptions,
            sessionData: sessionData
        )

    case .smsSent(let phoneNumber):
        let code = "... code from SMS ..."
        try await client.submitSecurityCode(
            .sms(code: code, phoneNumberId: phoneNumber.id),
            sessionData: sessionData
        )

    case .securityKey:
        // Add the XcodesLoginKitSecurityKey product and call
        // submitSecurityKeyPinCode(_:sessionData:authOptions:).
        break
    }

case .unauthenticated, .notAppleDeveloper:
    break
}
```

`Client` resolves Apple's public sign-in widget key in this order:

1. An explicit key supplied by the application, when present.
2. A key previously saved in XcodesLoginKit's in-memory or on-disk cache.
3. The `widgetKey` in App Store Connect's unauthenticated `/logout` redirect.
4. The legacy App Store Connect Olympus configuration endpoint as a final fallback.

The sign-out lookup uses a separate cookie-free session and does not follow the redirect. Following
that redirect would perform a real sign-out, so the authentication session is never used for this
request.

Supply an explicit key without changing the library:

```swift
let client = Client(serviceKeyProvider: .fixed("current-public-widget-key"))
```

For dynamic configuration, supply an asynchronous, `Sendable` loader:

```swift
let client = Client(
    serviceKeyProvider: AppleServiceKeyProvider {
        try await configuration.appleServiceKey()
    }
)
```

Successful automatic lookups are cached on a best-effort basis. Cache read or write failures do not
block authentication. If every network source fails, the client throws
`AuthenticationError.serviceKeyResolutionFailed(attempts:)`, whose localized description includes
the source-specific failures and HTTP status codes when available.

### Main flow

1. Create a `Client`. Pass a custom `URLSession` if you want isolated cookie storage.
2. Call `authenticationState(accountName:password:)`.
3. Switch on `AuthenticationState`.
4. Complete any required federated authentication or second-factor challenge.
5. Call `validateSession()` later to check whether stored cookies are still valid.
6. Call `signout()` to clear the client's cookies.

### Federated Apple IDs

Federated accounts return `.waitingForFederatedAuthentication`. Open `FederationResponse.idpURL`
in a browser, let the user finish identity-provider sign-in, then pass the final callback URL to
`validateFederatedCallbackURL(_:)` or `validateFederatedCallbackURLString(_:)`.

### Reusing fastlane sessions

If the user already has a fastlane session, load its cookies into a session and pass that session
to `Client`:

```swift
let loader = FastlaneSessionLoader()
let session = try loader.session(
    fastlaneUser: "name@example.com",
    environmentValue: { ProcessInfo.processInfo.environment[$0] }
)

let client = Client(urlSession: session)
let state = try await client.validateSession()
```

Use `FastlaneSessionLoader.Constants.fastlaneSessionEnvVarName` as `fastlaneUser` to load cookies
from `FASTLANE_SESSION` instead of `~/.fastlane/spaceship/<apple-id>/cookie`.

### Higher-level session management

`AppleSessionService` wraps the low-level client with dependency-injected environment lookup,
keychain storage, prompts, browser opening, validation, login, and logout. It is a good fit for
command-line tools that want a "login if needed" workflow while still controlling where credentials
are stored and how users are prompted.

### Security keys

Add the `XcodesLoginKitSecurityKey` product when you need FIDO2 security-key support:

```swift
.product(name: "XcodesLoginKitSecurityKey", package: "XcodesLoginKit")
```

When the login state is `.waitingForSecondFactor(.securityKey, authOptions, sessionData)`, call
`submitSecurityKeyPinCode(_:sessionData:authOptions:)`.
