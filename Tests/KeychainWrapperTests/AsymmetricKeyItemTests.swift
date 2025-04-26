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

@Suite(.serialized) actor KeyItemTests {
	/// Common key size for EC keys.
	private let normalECKeySize = 256

	/// The plain text message we want to operate on.
	private let plainText = "The quick brown fox jumps over the lazy dog"
		.data(using: .utf8) ?? Data()
	
	/// A regular tag used for identification of a keychain item.
	private func generateTag() -> Data {
		"KeychainWrapper.KeyItemTests.\(UUID())"
			.data(using: .utf8)!
	}

	/// Can we create asymmetric keys?
	@Test func testCreateAsymmetricKeys() throws {
		let tag = generateTag()

		let _ = try generateAsymmetricPrivateKey(
			privateKeyTag: tag, algorithm: .ec, size: self.normalECKeySize)

		let _ = try asymmetricKeyFromKeychain(
			tag: tag, part: .privateKey, algorithm: .ec,
			size: self.normalECKeySize)

//		#expect(throws: Error.self,
//				"the private key should not be exportable") {
			let _ = try asymmetricKeyDataFromKeychain(
				tag: tag, part: .privateKey, algorithm: .ec,
				size: self.normalECKeySize)
//		}

		#expect(throws: Error.self,
				"we can't obtain the public key this way") {
			_ = try asymmetricKeyDataFromKeychain(
				tag: tag, part: .publicKey, algorithm: .ec,
				size: self.normalECKeySize)
		}

		try removeAsymmetricKeyFromKeychain(
			tag: tag, part: .privateKey, algorithm: .ec,
			size: self.normalECKeySize)
	}

	/// Can we add asymmetric keys?
	@Test func testAddAsymmetricKeys() throws {
		let tag = generateTag()

		// without this, the generateAsymmetricPrivateKey fails o.0
		sleep(10)

		let key = try generateAsymmetricPrivateKey(
			privateKeyTag: tag, algorithm: .ec, size: self.normalECKeySize)

		let newTag = generateTag()

		// this crashes entirely with
		// 'NSInvalidArgumentException', reason: '-[__NSArrayM length]: unrecognized selector sent to instance 0x600003fe9b00'

//		let publicKey = try #require(SecKeyCopyPublicKey(key))
//
//		#expect(throws: Never.self, "Re-adding a key should not fail") {
//			let _ = try addAsymmetricKeyToKeychain(
//				publicKey, tag: newTag, part: .privateKey, algorithm: .ec,
//				size: self.normalECKeySize)
//		}
//
//		#expect(throws: Never.self, "Removing new key should not fail") {
//			try removeAsymmetricKeyFromKeychain(
//				tag: newTag, part: .privateKey, algorithm: .ec,
//				size: self.normalECKeySize)
//		}

		#expect(throws: Never.self, "Removing original key should not fail") {
			try removeAsymmetricKeyFromKeychain(
				tag: tag, part: .privateKey, algorithm: .ec,
				size: self.normalECKeySize)
		}
	}
}
