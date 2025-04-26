//
//  AsymmetricCrypto.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 06.10.2022.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

/// Represents a public or private asymmetric key in the keychain.
public struct AsymmetricKeyProperties: Sendable, Codable {
	/// Padding to be used for cryptographic operations applying this key.
	fileprivate static
	let signaturePadding: SecPadding = [],
		encryptionPadding: SecPadding = [] // .PKCS1SHA256

	/// Which properties should be serialized; automatically read by ``Codable`` protocol.
	enum CodingKeys: String, CodingKey {
		case part, algorithm, size
	}

	/// Cryptographic property of `key`.
	public
	let part: AsymmetricKeyPart, algorithm: AsymmetricAlgorithm, size: Int

	public
	init(part: AsymmetricKeyPart, algorithm: AsymmetricAlgorithm, size: Int) {
		self.part = part
		self.algorithm = algorithm
		self.size = size
	}
}

/// Represents a public or private asymmetric key in the keychain.
public struct AsymmetricKeyKeychainID: Sendable {

	/// Which properties should be serialized; automatically read by ``Codable`` protocol.
	enum CodingKeys: String, CodingKey {
		case tag, properties
	}

	/// Cryptographic property of `key`.
	public let tag: Data, properties: AsymmetricKeyProperties

	public init(tag: Data, properties: AsymmetricKeyProperties) {
		self.tag = tag
		self.properties = properties
	}
}

extension AsymmetricKeyKeychainID {
	/// Opaque container of the asymmetric key this class wraps around. Non-`Sendable`.
	fileprivate func key() throws -> SecKey {
		return try asymmetricKeyFromKeychain(
			tag: tag,
			part: properties.part,
			algorithm: properties.algorithm,
			size: properties.size)
	}

	/// Removes the key from the keychain. Does not throw if nothing was removed.
	public func removeFromKeychain() throws {
		try removeAsymmetricKeyFromKeychain(
			tag: tag, part: properties.part,
			algorithm: properties.algorithm, size: properties.size)
	}

	/// Whether this key can be used.
	public var available: Bool {
		get throws {
			do {
				_ = try key()
				return true
			} catch {
				if (error as NSError).code == errSecItemNotFound {
					return false
				} else {
					throw error
				}
			}
		}
	}
}

/// Represents a public or private asymmetric key in the keychain.
public struct AsymmetricKeyInMemory: Sendable {
	/// Which properties should be serialized; automatically read by ``Codable`` protocol.
	enum CodingKeys: String, CodingKey {
		case data, properties
	}

	/// Cryptographic property of `key`.
	public let data: Data, properties: AsymmetricKeyProperties

	public init(data: Data, properties: AsymmetricKeyProperties) {
		self.data = data
		self.properties = properties
	}
}

extension AsymmetricKeyInMemory {
	/// Opaque container of the asymmetric key this class wraps around. Non-`Sendable`.
	fileprivate func key() throws -> SecKey {
		return try secKey(from: data,
						  type: properties.algorithm.keyType,
						  size: properties.size,
						  keyClass: properties.part.keyClass)
	}

	/// Writes the key into the keychain.
	public func save(tag: Data) throws -> AsymmetricKeyBacking {
		try addAsymmetricKeyToKeychain(
			key(), tag: tag, part: properties.part,
			algorithm: properties.algorithm, size: properties.size)

		return AsymmetricKeyBacking.keychain(
			.init(tag: tag, properties: properties))
	}
}

public protocol AsymmetricKeyBase: Sendable {
	/// See ``SecKeyGetBlockSize(_:)``.
	var blockSize: Int { get throws }

	/// Obtains the binary representation of this key.
	///
	/// Should only be used for public keys, since private keys should remain in the keychain.
	///
	/// - Returns: The mathematical representation of the key in binary Format.
	/// See ``SecKeyCopyExternalRepresentation(_:_:)`` for more information.
	///
	/// - Throws: An `NSError` if the key is not exportable.
	func externalRepresentation() throws -> Data
}

public enum AsymmetricKeyBacking {
	case memory(AsymmetricKeyInMemory), keychain(AsymmetricKeyKeychainID)
}

extension AsymmetricKeyBacking {
	public var properties: AsymmetricKeyProperties {
		switch self {
		case .memory(let inMemory):
			return inMemory.properties
		case .keychain(let keychainID):
			return keychainID.properties
		}
	}
}

/// Parses `data` based on the key properties provided to this method.
///
/// - Throws: An `NSError` if `data` does not contain an appropriate representation of a key.
fileprivate func secKey(from data: Data, type: CFString, size: Int,
						keyClass: CFString) throws -> SecKey {
	let attributes: [CFString : Any] = [
		kSecAttrKeyType:       type,
		kSecAttrKeySizeInBits: size,
		kSecAttrKeyClass:      keyClass]

	var error: Unmanaged<CFError>?
	guard let key = SecKeyCreateWithData(data as CFData,
										 attributes as CFDictionary,
										 &error) else {
		throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
	}

	return key
}

extension AsymmetricKeyBacking {
	/// Opaque container of the asymmetric key this class wraps around. Non-`Sendable`.
	fileprivate func key() throws -> SecKey {
		switch self {
		case .memory(let key):
			return try key.key()
		case .keychain(let keyID):
			return try keyID.key()
		}
	}

	/// Whether this key can be used.
	public var available: Bool {
		get throws {
			switch self {
			case .memory(_):
				return false
			case .keychain(let keyID):
				return try keyID.available
			}
		}
	}
}

extension AsymmetricKeyBacking: AsymmetricKeyBase {

	/// See ``SecKeyGetBlockSize(_:)``.
	public var blockSize: Int {
		get throws {
			return SecKeyGetBlockSize(try key())
		}
	}

	/// Obtains the binary representation of this key.
	///
	/// Should only be used for public keys, since private keys should remain in the keychain.
	///
	/// - Returns: The mathematical representation of the key in binary Format.
	/// See ``SecKeyCopyExternalRepresentation(_:_:)`` for more information.
	///
	/// - Throws: An `NSError` if the key is not exportable.
	public func externalRepresentation() throws -> Data {
		switch self {
		case .memory(let key):
			return key.data
		case .keychain(let keyID):
			return try asymmetricKeyDataFromKeychain(
				tag: keyID.tag, part: keyID.properties.part,
				algorithm: keyID.properties.algorithm,
				size: keyID.properties.size)
//			var error: Unmanaged<CFError>?
//			guard let data = SecKeyCopyExternalRepresentation(
//				try key(), &error) as Data? else {
//				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
//			}
//			return data
		}
	}
}

/// Represents a public asymmetric key.
public protocol AsymmetricPublicKey: AsymmetricKeyBase {
	/// Checks the integrity of `message` by calculating whether the `signature`
	/// was computed with the corresponding private key to this public key.
	///
	/// - Throws: An `NSError` if the signature is invalid or the verification process failed.
	func verify(message data: Data, signature: Data) throws

	/// Encrypts `message`, s.t. it can only be decrypted by the corresponding
	/// private key to this public key.
	///
	/// - Returns: Cipher text of `message`, which can be decrypted with
	/// ``AsymmetricPrivateKey/decrypt(message:)``.
	///
	/// - Throws: An `NSError` if the encryption process failed.
	func encrypt(message plainText: Data) throws -> Data
}

extension AsymmetricKeyBacking: AsymmetricPublicKey {

	/// Checks the integrity of `message` by calculating, whether the `signature`
	/// was computed with the corresponding private key to this public key.
	///
	/// - Throws: An `NSError` if the signature is invalid or the verification process failed.
	public func verify(message data: Data, signature: Data) throws {
		let key = try key()

		let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
		guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
			let errorFormat = NSLocalizedString(
				"Elliptic curve algorithm %@ does not support verifying.",
				tableName: "AsymmetricCrypto", bundle: .module,
				comment: "Error description for verifying exception, which should never actually occur")

			let errorDescription = String(
				format: errorFormat,
				SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256.rawValue as String)
			throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError,
						  userInfo: [NSLocalizedDescriptionKey : errorDescription])
		}

		var error: Unmanaged<CFError>?
		guard SecKeyVerifySignature(key, algorithm, data as CFData,
									signature as CFData, &error) else {
			throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
		}
	}

	/// Encrypts `message`, s.t. it can only be decrypted by the corresponding private key to this public key.
	///
	/// - Returns: Cipher text of `message`, which can be decrypted with ``AsymmetricPrivateKey/decrypt(message:)``.
	///
	/// - Throws: An `NSError` if the encryption process failed.
	public func encrypt(message plainText: Data) throws -> Data {
		let key = try key()

		// does not work: ecdhKeyExchangeStandardX963SHA256, ecdhKeyExchangeCofactor
		let algorithm = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
		guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
			let errorFormat = NSLocalizedString("Elliptic curve algorithm %@ does not support encryption.",
			tableName: "AsymmetricCrypto", bundle: .module,
			comment: "Error description for verifying exception, which should never actually occur")

			let errorDescription = String(format: errorFormat, algorithm.rawValue as String)
			throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError,
						  userInfo: [NSLocalizedDescriptionKey : errorDescription])
		}

		let padding = 0 // TODO find out how much it is for ECDH
		guard plainText.count <= (SecKeyGetBlockSize(key)-padding) else {
			let errorFormat = NSLocalizedString("Plain text length (%d) exceeds block size %d",
			tableName: "AsymmetricCrypto", bundle: .module,
			comment: "Exception when trying to encrypt too-big data.")

			let errorDescription = String(format: errorFormat, plainText.count,
										  SecKeyGetBlockSize(key)-padding)
			throw NSError(domain: NSCocoaErrorDomain,
						  code: NSValidationErrorMaximum,
						  userInfo: [NSLocalizedDescriptionKey : errorDescription])
		}

		var error: Unmanaged<CFError>?
		guard let cipherText = SecKeyCreateEncryptedData(
			key, algorithm, plainText as CFData, &error) as Data? else {
			throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
		}

		return cipherText
	}
}

/// Represents a public asymmetric key.
public protocol AsymmetricPrivateKey: AsymmetricKeyBase {
	/// Produces a digital signature for `message`, which can be used to verify its integrity.
	///
	/// - Returns: The digital signature of `message`, which can be checked with
	/// ``AsymmetricPublicKey/verify(message:signature:)``.
	///
	/// - Throws: An `NSError` if the sign process failed.
	func sign(message data: Data) throws -> Data

	/// Produces plain text for encrypted `message`.
	///
	/// - Returns: The plain text of `message`, which was encrypted with
	/// ``AsymmetricPublicKey/encrypt(message:)``.
	///
	/// - Throws: An `NSError` if the decryption process failed.
	func decrypt(message cipherText: Data) throws -> Data

	/// Gets the public key associated with this private key.
	///
	/// - Returns: The public key associated with this private key.
	///
	/// - Throws: An `NSError` if the public key cannot be obtained.
	func copyPublicKey() throws -> AsymmetricPublicKey
}

/// Represents a private asymmetric key.
extension AsymmetricKeyBacking: AsymmetricPrivateKey {

	/// Produces a digital signature for `message`, which can be used to verify its integrity.
	///
	/// - Returns: The digital signature of `message`, which can be checked with
	/// ``AsymmetricPublicKey/verify(message:signature:)``.
	///
	/// - Throws: An `NSError` if the sign process failed.
	public func sign(message data: Data) throws -> Data {
		let key = try key()

		let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
		guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
			let errorFormat = NSLocalizedString("Elliptic curve algorithm %@ does not support signing.",
			tableName: "AsymmetricCrypto", bundle: .module,
			comment: "Error description for signing exception, which should never actually occur")

			let errorDescription = String(format: errorFormat,
										  algorithm.rawValue as String)
			throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError,
						  userInfo: [NSLocalizedDescriptionKey : errorDescription])
		}

		var error: Unmanaged<CFError>?
		guard let signature = SecKeyCreateSignature(
			key, algorithm, data as CFData, &error) as Data? else {
			throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
		}

		return signature
	}

	/// Produces plain text for encrypted `message`.
	///
	/// - Returns: The plain text of `message`, which was encrypted with ``AsymmetricPublicKey/encrypt(message:)``.
	///
	/// - Throws: An `NSError` if the decryption process failed.
	public func decrypt(message cipherText: Data) throws -> Data {
		let key = try key()

		let algorithm = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
		guard SecKeyIsAlgorithmSupported(key, .decrypt, algorithm) else {
			let errorFormat = NSLocalizedString("Elliptic curve algorithm %@ does not support decryption.",
				tableName: "AsymmetricCrypto", bundle: .module,
				comment: "Error description for decryption exception, which should never actually occur")

			let errorDescription = String(format: errorFormat,
										  algorithm.rawValue as String)
			throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError,
						  userInfo: [NSLocalizedDescriptionKey : errorDescription])
		}

		var error: Unmanaged<CFError>?
		guard let clearText = SecKeyCreateDecryptedData(
			key, algorithm, cipherText as CFData, &error) as Data? else {
			throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
		}

		return clearText
	}

	/// Gets the public key associated with this private key.
	///
	/// - Returns: The public key associated with this private key.
	///
	/// - Throws: An `NSError` if the public key cannot be obtained.
	public func copyPublicKey() throws -> any AsymmetricPublicKey {
		// Note: it is not possible to return a .keychain backing, since
		// we only store the private key in the keychain and we can't reference
		// it with kSecAttrKeyClassPublic.

		let publicKeyProperties = AsymmetricKeyProperties(
			part: .publicKey, algorithm: self.properties.algorithm,
			size: self.properties.size)

		let key = try key()

		guard let publicKey = SecKeyCopyPublicKey(key) else {
			throw makeFatalError()
		}

		var error: Unmanaged<CFError>?
		guard let data = SecKeyCopyExternalRepresentation(
			publicKey, &error) as Data? else {
			throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
		}

		return AsymmetricKeyBacking.memory(
			.init(data: data, properties: publicKeyProperties))
	}
}

/// Container for an asymmetric key pair.
public struct KeyPair: Sendable {
	/// Private part of this key pair, which needs to be kept secure.
	private let privateKeyBacking: AsymmetricKeyBacking

	/// Public part of this key pair, which can be passed around publicly.
	public var publicKey: AsymmetricPublicKey {
		get throws {
			return try privateKeyBacking.copyPublicKey()
		}
	}

	/// Keychain item property.
	public let tag: Data

	/// The block size of the private key.
	public var privateKeyBlockSize: Int {
		get throws {
			return try privateKeyBacking.blockSize
		}
	}

	/// The block size of the private key.
	public var publicKeyBlockSize: Int {
		get throws {
			return try publicKey.blockSize
		}
	}

	/// Whether this key can be used.
	public var available: Bool {
		get throws {
			return try privateKeyBacking.available
		}
	}

	/// Generates a key pair and stores it in the keychain.
	///
	/// > Note: Added in v1.1.0, updated in v3.
	public init(tag: Data, algorithm: AsymmetricAlgorithm, size: Int,
				useEnclave: Bool = false) throws {
		self.tag = tag

		_ = try generateAsymmetricPrivateKey(
			privateKeyTag: tag, algorithm: algorithm, size: size,
			useEnclave: useEnclave)

		self.privateKeyBacking = .keychain(.init(tag: tag, properties: .init(
			part: .privateKey, algorithm: algorithm, size: size)))
	}

	/// Loads a key pair from the system keychain.
	///
	/// > Note: Added in v1.1.0.
	public init(fromKeychainWithTag tag: Data, algorithm: AsymmetricAlgorithm,
				size: Int) {
		self.tag = tag

		self.privateKeyBacking = .keychain(.init(tag: tag, properties: .init(
			part: .privateKey, algorithm: algorithm, size: size)))
	}

	/// Deletes the key in the keychain.
	public func removeFromKeychain() throws {
		if case .keychain(let keyID) = self.privateKeyBacking {
			try keyID.removeFromKeychain()
		}
	}

	/// Obtains the binary representation of the public key, s.t. it can be distributed.
	public func externalPublicKey() throws -> Data {
		return try publicKey.externalRepresentation()
	}

	/// Signs `message` using the private key; see also ``AsymmetricPrivateKey/sign(message:)``.
	public func sign(message: Data) throws -> Data {
		return try privateKeyBacking.sign(message: message)
	}

	/// Verifies `message` using the public key; see also ``AsymmetricPublicKey/verify(message:signature:)``.
	public func verify(message: Data, signature: Data) throws {
		try publicKey.verify(message: message, signature: signature)
	}

	/// Encrypts `message` using the public key; see also ``AsymmetricPublicKey/encrypt(message:)``.
	public func encrypt(message plainText: Data) throws -> Data {
		return try publicKey.encrypt(message: plainText)
	}

	/// Decrypts `message` using the private key; see also ``AsymmetricPrivateKey/decrypt(message:)``.
	public func decrypt(message cipherText: Data) throws -> Data {
		return try privateKeyBacking.decrypt(message: cipherText)
	}
}

