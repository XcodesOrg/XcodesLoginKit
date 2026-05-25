import Foundation

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

    public struct Dependencies: Sendable {
        public var environmentValue: EnvironmentValue
        public var defaultUsername: DefaultUsername
        public var setDefaultUsername: SetDefaultUsername
        public var keychainString: KeychainString
        public var keychainSet: KeychainSet
        public var keychainRemove: KeychainRemove
        public var readLine: ReadLine
        public var readLongLine: ReadLongLine
        public var readSecureLine: ReadSecureLine
        public var validateSession: ValidateSession
        public var login: Login
        public var checkIsFederated: CheckIsFederated
        public var validateFederatedCallbackURL: ValidateFederatedCallbackURL
        public var openURL: OpenURL
        public var signout: Signout
        public var loadData: LoadData
        public var log: Log

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

    public func validateADCSession(path: String) async throws {
        try await DeveloperPortalSessionService(
            loadData: dependencies.loadData
        ).validateADCSession(path: path)
    }

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

    public func logout() async throws {
        guard let username = findUsername() else { throw Error.notAuthenticated }

        await dependencies.signout()
        try dependencies.keychainRemove(username)
        try dependencies.setDefaultUsername(nil)
    }
}

public extension AppleSessionService {
    enum Error: LocalizedError, Equatable {
        case missingUsernameOrPassword
        case notAuthenticated

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
