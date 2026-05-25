import Foundation

/// Coordinates credential lookup, prompting, login, validation, and logout for Apple Developer sessions.
///
/// `AppleSessionService` is the high-level API for command-line tools and apps that want an injectable
/// workflow around ``Client``. It can read credentials from environment variables or a keychain, prompt
/// when credentials are missing, open a browser for federated accounts, and remember the default username
/// after a successful login.
public actor AppleSessionService {
    public typealias EnvironmentValue = @Sendable (String) -> String?
    public typealias DefaultUsername = @Sendable () -> String?
    public typealias SetDefaultUsername = @Sendable (String?) throws -> Void
    public typealias KeychainString = @Sendable (String) throws -> String?
    public typealias KeychainSet = @Sendable (String, String) throws -> Void
    public typealias KeychainRemove = @Sendable (String) throws -> Void
    public typealias ReadLine = @Sendable (String) -> String?
    public typealias ReadLongLine = @Sendable (String) -> String?
    public typealias ReadSecureLine = @Sendable (String) -> String?
    public typealias ValidateSession = @Sendable () async throws -> Void
    public typealias Login = @Sendable (String, String) async throws -> Void
    public typealias CheckIsFederated = @Sendable (String) async throws -> FederationResponse
    public typealias ValidateFederatedCallbackURL = @Sendable (String) async throws -> Void
    public typealias OpenURL = @Sendable (URL) -> Void
    public typealias Signout = @Sendable () async -> Void
    public typealias LoadData = @Sendable (URLRequest) async throws -> (Data, URLResponse)
    public typealias Log = @Sendable (String) -> Void

    /// Dependencies used by ``AppleSessionService`` to interact with the host app and storage.
    ///
    /// Supply closures for environment lookup, keychain access, prompting, browser opening, networking,
    /// and the underlying login operations. This keeps the service testable and lets each app decide how
    /// credentials and user interaction should work.
    public struct Dependencies: Sendable {
        /// Reads a process environment value.
        public var environmentValue: EnvironmentValue
        /// Returns the remembered default Apple ID, if any.
        public var defaultUsername: DefaultUsername
        /// Stores or clears the remembered default Apple ID.
        public var setDefaultUsername: SetDefaultUsername
        /// Reads a string from secure storage for a username.
        public var keychainString: KeychainString
        /// Stores a string in secure storage for a username.
        public var keychainSet: KeychainSet
        /// Removes a username's stored secret.
        public var keychainRemove: KeychainRemove
        /// Prompts for a single line of input.
        public var readLine: ReadLine
        /// Prompts for a long line of input, such as a pasted browser callback URL.
        public var readLongLine: ReadLongLine
        /// Prompts for hidden input, such as a password.
        public var readSecureLine: ReadSecureLine
        /// Validates the current Apple session.
        public var validateSession: ValidateSession
        /// Performs username and password login.
        public var login: Login
        /// Checks whether an Apple ID uses federated authentication.
        public var checkIsFederated: CheckIsFederated
        /// Completes federated login from a pasted callback URL string.
        public var validateFederatedCallbackURL: ValidateFederatedCallbackURL
        /// Opens a URL in the host app or system browser.
        public var openURL: OpenURL
        /// Signs out from the underlying Apple session.
        public var signout: Signout
        /// Loads data for a URL request, used by developer-portal validation.
        public var loadData: LoadData
        /// Receives user-visible progress or recovery messages.
        public var log: Log

        /// Creates a dependency container for ``AppleSessionService``.
        public init(
            environmentValue: @escaping EnvironmentValue,
            defaultUsername: @escaping DefaultUsername,
            setDefaultUsername: @escaping SetDefaultUsername,
            keychainString: @escaping KeychainString,
            keychainSet: @escaping KeychainSet,
            keychainRemove: @escaping KeychainRemove,
            readLine: @escaping ReadLine,
            readLongLine: @escaping ReadLongLine,
            readSecureLine: @escaping ReadSecureLine,
            validateSession: @escaping ValidateSession,
            login: @escaping Login,
            checkIsFederated: @escaping CheckIsFederated,
            validateFederatedCallbackURL: @escaping ValidateFederatedCallbackURL,
            openURL: @escaping OpenURL,
            signout: @escaping Signout,
            loadData: @escaping LoadData,
            log: @escaping Log = { _ in }
        ) {
            self.environmentValue = environmentValue
            self.defaultUsername = defaultUsername
            self.setDefaultUsername = setDefaultUsername
            self.keychainString = keychainString
            self.keychainSet = keychainSet
            self.keychainRemove = keychainRemove
            self.readLine = readLine
            self.readLongLine = readLongLine
            self.readSecureLine = readSecureLine
            self.validateSession = validateSession
            self.login = login
            self.checkIsFederated = checkIsFederated
            self.validateFederatedCallbackURL = validateFederatedCallbackURL
            self.openURL = openURL
            self.signout = signout
            self.loadData = loadData
            self.log = log
        }
    }

    private let xcodesUsername = "XCODES_USERNAME"
    private let xcodesPassword = "XCODES_PASSWORD"
    private let dependencies: Dependencies

    /// Creates a service with the host-provided dependencies.
    public init(dependencies: Dependencies) {
        self.dependencies = dependencies
    }

    private func findUsername() -> String? {
        if let username = dependencies.environmentValue(xcodesUsername) {
            return username
        } else if let username = dependencies.defaultUsername() {
            return username
        }
        return nil
    }

    private func findPassword(withUsername username: String) -> String? {
        if let password = dependencies.environmentValue(xcodesPassword) {
            return password
        } else if let password = try? dependencies.keychainString(username) {
            return password
        }
        return nil
    }

    /// Validates that the current session is authorized to access an Apple Developer download path.
    ///
    /// - Parameter path: The developer download path to validate, such as a path from an Xcode release.
    public func validateADCSession(path: String) async throws {
        try await DeveloperPortalSessionService(
            loadData: dependencies.loadData
        ).validateADCSession(path: path)
    }

    /// Ensures that a valid Apple session exists, prompting or signing in only when needed.
    ///
    /// The service first calls `validateSession`. If that fails, it looks for a username from the
    /// provided argument, `XCODES_USERNAME`, or the remembered default username. Passwords are read from
    /// `XCODES_PASSWORD`, secure storage, or `readSecureLine`. Federated accounts open the identity
    /// provider URL and ask the user to paste the callback URL.
    /// - Parameters:
    ///   - providedUsername: A username to try before environment or default values.
    ///   - shouldPromptForPassword: Pass `true` to ignore saved passwords and force a password prompt.
    public func loginIfNeeded(withUsername providedUsername: String? = nil, shouldPromptForPassword: Bool = false) async throws {
        do {
            try await dependencies.validateSession()
            return
        } catch {
            var possibleUsername = providedUsername ?? findUsername()
            var hasPromptedForUsername = false
            if possibleUsername == nil {
                possibleUsername = dependencies.readLine("Apple ID: ")
                hasPromptedForUsername = true
            }
            guard let username = possibleUsername else { throw Error.missingUsernameOrPassword }

            let federationResponse = try await dependencies.checkIsFederated(username)
            if federationResponse.federated {
                try await handleFederatedLogin(username: username, federationResponse: federationResponse)
                return
            }

            let passwordPrompt: String
            if hasPromptedForUsername {
                passwordPrompt = "Apple ID Password: "
            } else {
                passwordPrompt = "Apple ID Password (\(username)): "
            }
            var possiblePassword = findPassword(withUsername: username)
            if possiblePassword == nil || shouldPromptForPassword {
                possiblePassword = dependencies.readSecureLine(passwordPrompt)
            }
            guard let password = possiblePassword else { throw Error.missingUsernameOrPassword }

            do {
                try await login(username, password: password)
            } catch {
                dependencies.log(error.localizedDescription)

                guard case AuthenticationError.invalidUsernameOrPassword = error else { throw error }

                dependencies.log("Try entering your password again")
                try await loginIfNeeded(withUsername: username, shouldPromptForPassword: true)
            }
        }
    }

    private func handleFederatedLogin(username: String, federationResponse: FederationResponse) async throws {
        guard let idpURL = federationResponse.idpURL else {
            throw AuthenticationError.federatedAuthenticationRequired
        }

        let orgName = federationResponse.federatedAuthIntro?.orgName ?? "your organization"
        let idpName = federationResponse.federatedAuthIntro?.idpName
        let orgNameWithIdp = idpName.map { "\(orgName) (\($0))" } ?? orgName

        dependencies.log("\n- This account uses federated authentication via \(orgNameWithIdp)")
        dependencies.log("- Your browser will open to complete sign-in")
        dependencies.log("- After signing in, you will be redirected to a blank page")
        dependencies.log("- Copy the URL from your browser's address bar, then return here and paste it")
        dependencies.log("\nOpening your browser...")
        dependencies.openURL(idpURL)

        guard let callbackURLString = dependencies.readLongLine("\nPaste the URL here: ") else {
            throw Error.missingUsernameOrPassword
        }

        try await dependencies.validateFederatedCallbackURL(callbackURLString)

        if dependencies.defaultUsername() != username {
            try? dependencies.setDefaultUsername(username)
        }
    }

    /// Logs in with an explicit username and password, then stores successful credentials.
    ///
    /// If Apple reports invalid credentials, the stored password for that username is removed.
    public func login(_ username: String, password: String) async throws {
        do {
            try await dependencies.login(username, password)
        } catch {
            if case AuthenticationError.invalidUsernameOrPassword = error {
                try? dependencies.keychainRemove(username)
            }

            throw error
        }

        try? dependencies.keychainSet(password, username)

        if dependencies.defaultUsername() != username {
            try? dependencies.setDefaultUsername(username)
        }
    }

    /// Signs out, removes the stored password, and clears the remembered default username.
    public func logout() async throws {
        guard let username = findUsername() else { throw Error.notAuthenticated }

        await dependencies.signout()
        try dependencies.keychainRemove(username)
        try dependencies.setDefaultUsername(nil)
    }
}

public extension AppleSessionService {
    /// Errors raised by the high-level session service before or after Apple authentication.
    enum Error: LocalizedError, Equatable {
        /// No username or password was available from dependencies or prompting.
        case missingUsernameOrPassword
        /// Logout was requested when no username could be found.
        case notAuthenticated

        /// A user-visible description of the service error.
        public var errorDescription: String? {
            switch self {
            case .missingUsernameOrPassword:
                return "Missing username or a password. Please try again."
            case .notAuthenticated:
                return "You are already signed out"
            }
        }
    }
}
