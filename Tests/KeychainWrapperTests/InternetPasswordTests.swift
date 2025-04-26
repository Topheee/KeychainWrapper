//
//  AsymmetricCryptoTests.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 13.04.25.
//  Copyright © 2025 Christopher Kobusch. All rights reserved.
//

// Platform Dependencies
import Foundation

// Test Dependencies
import Testing

@testable import KeychainWrapper

actor InternetPasswordTests {
	private let normalAccount = "MyTestSecret"
	private let normalSecurityDomain = "MyTestSecret"
	private let normalServer = "example.com"
	private let normalPort = 443
	private let normalPath = "/"
	private let normalAuthenticationType = AuthenticationTypeKeychainAttribute.`default`
	private let normalProtocol = ProtocolKeychainAttribute.https

	/// Can we read and write to the keychain?
	@Test func testNormalOperation() throws {
		let pwData = "a".data(using: .utf8) ?? Data()

		try persistInternetPasswordInKeychain(
			pwData, account: self.normalAccount,
			securityDomain: self.normalSecurityDomain,
			server: self.normalServer, port: self.normalPort,
			path: self.normalPath, protocolAttribute: self.normalProtocol,
			authenticationType: self.normalAuthenticationType)

		defer {
			try? removeInternetPasswordFromKeychain(
				account: self.normalAccount,
				securityDomain: self.normalSecurityDomain,
				server: self.normalServer, port: self.normalPort,
				path: self.normalPath, protocolAttribute: self.normalProtocol,
				authenticationType: self.normalAuthenticationType)
		}

		#expect(try internetPasswordFromKeychain(
			account: self.normalAccount,
			securityDomain: self.normalSecurityDomain,
			server: self.normalServer, port: self.normalPort,
			path: self.normalPath, protocolAttribute: self.normalProtocol,
			authenticationType: self.normalAuthenticationType) == pwData)
	}

	@Test func testDeleteFailsOnNonExistentAccount() throws {
		#expect(throws: Error.self) {
			try removeInternetPasswordFromKeychain(
				account: "non-existing",
				securityDomain: self.normalSecurityDomain,
				server: self.normalServer, port: self.normalPort,
				path: self.normalPath, protocolAttribute: self.normalProtocol,
				authenticationType: self.normalAuthenticationType)
		}
	}
}
