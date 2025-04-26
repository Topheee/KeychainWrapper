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

@Suite(.serialized) actor AsymmetricCryptoTests {
	/// A regular tag used for identification of a key.
	private func generateTag(for part: AsymmetricKeyPart) -> Data {
		"KeychainWrapper.\(part.keyClass).\(UUID())"
			.data(using: .utf8)!
	}

	/// Common size for elliptic curve keys.
	private let normalECKeySize = 256

	/// Common size for elliptic curve keys.
	private let normalECPrivateKeyBlockSize = 72

	/// Common size for elliptic curve keys.
	private let normalECPublicKeyBlockSize = 32

	/// The message we want to operate on.
	private let plainText = "The quick brown fox jumps over the lazy dog"
		.data(using: .utf8) ?? Data()

	/// Creates a key pair. Make sure to remove it from keychain at the end!
	private func getKeyPair() throws -> KeyPair {
		let privateTag = generateTag(for: .privateKey)

		return try KeyPair(
			tag: privateTag, algorithm: .ec, size: self.normalECKeySize,
			useEnclave: false)
	}

	/// Can we obtain the block size?
	@Test func testKeyPairBlockSize() throws {
		let keyPair = try getKeyPair()
		defer { try? keyPair.removeFromKeychain() }

		#expect(try keyPair.privateKeyBlockSize ==
				self.normalECPrivateKeyBlockSize)
	}

	/// Can we obtain the public key?
	@Test func testKeyPairPublicKey() throws {
		let keyPair = try getKeyPair()
		defer { try? keyPair.removeFromKeychain() }

		let publicKey = try keyPair.publicKey
		#expect(try keyPair.publicKeyBlockSize == publicKey.blockSize)
	}

	/// Can we sign and verify?
	@Test func testKeyPairSignVerify() throws {
		let keyPair = try getKeyPair()
		defer { try? keyPair.removeFromKeychain() }

		let signature = try keyPair.sign(message: self.plainText)

		try keyPair.verify(
			message: self.plainText, signature: signature)
	}

	/// Can we delete the key pair?
	@Test func testDeleteKeyPair() throws {
		let keyPair = try getKeyPair()

		try keyPair.removeFromKeychain()
	}

	/// Using a deleted key pair should throw an error.
	@Test func testUseDeletedKeyPair() throws {
		let keyPair = try getKeyPair()
		defer { try? keyPair.removeFromKeychain() }

		#expect(try keyPair.available == true)

		_ = try keyPair.sign(message: self.plainText)

		try keyPair.removeFromKeychain()

		#expect(try keyPair.available == false)

		#expect(throws: Error.self) {
			_ = try keyPair.sign(message: self.plainText)
		}
	}

	/// Can we encrypt and decrypt data?
	@Test func testEncryptDecrypt() throws {
		let keyPair = try getKeyPair()
		defer { try? keyPair.removeFromKeychain() }

		// Error Domain=NSCocoaErrorDomain Code=2047
		// "Plain text length (43) exceeds block size 32"
		#expect(throws: NSError.self) {
			try keyPair.encrypt(message: self.plainText)
		}

		let plainTextBlock = Data(repeating: UInt8.random(in: 0..<UInt8.max),
								  count: try keyPair.publicKeyBlockSize)

		// we encrypt with the public key (s.t. only the possessor of the
		// private key can decrypt)
		let cipherText = try keyPair.encrypt(message: plainTextBlock)

		#expect(
			try keyPair.decrypt(message: cipherText) == plainTextBlock)
	}

	/// An ephemeral key should be found by tag.
	@Test func testFindKeyPair() throws {
		let keyPair = try getKeyPair()
		defer { try? keyPair.removeFromKeychain() }

		#expect(try keyPair.available == true)

		// Since the key pair was not persisted we should not be able to obtain
		// it from the keychain.
		let referencedKeyPair = KeyPair(
			fromKeychainWithTag: keyPair.tag, algorithm: .ec,
			size: self.normalECKeySize)

		#expect(try referencedKeyPair.available == true)

		let refPubKey = try referencedKeyPair.externalPublicKey()

		let refPubKey2 = try referencedKeyPair.externalPublicKey()

		#expect(refPubKey == refPubKey2)

		let originalPubKey = try keyPair.externalPublicKey()

		#expect(refPubKey == originalPubKey)

		let plainTextBlock = Data(repeating: UInt8.random(in: 0..<UInt8.max),
								  count: try referencedKeyPair.publicKeyBlockSize)

		let cipherText = try referencedKeyPair.encrypt(message: plainTextBlock)

		#expect(try keyPair.decrypt(message: cipherText) == plainTextBlock)

		let signature = try referencedKeyPair.sign(message: cipherText)

		try keyPair.verify(message: cipherText, signature: signature)

		try referencedKeyPair.removeFromKeychain()

		#expect(try referencedKeyPair.available == false)

		#expect(try keyPair.available == false)
	}


	/// Does converting the public key to binary and back work?
	@Test func testSerialization() throws {
		let keyPair = try getKeyPair()
		defer { try? keyPair.removeFromKeychain() }

		let publicKeyData = try keyPair.publicKey.externalRepresentation()

		let encoder = JSONEncoder()
		let encodedData = try encoder.encode(publicKeyData)

		let decoder = JSONDecoder()
		let decodedPublicKeyData = try decoder.decode(Data.self, from: encodedData)

		#expect(publicKeyData == decodedPublicKeyData)
	}
}
