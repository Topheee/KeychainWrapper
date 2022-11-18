//
//  AsymmetricCrypto.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 06.10.2022.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

/// Represents a public or private asymmetric key.
public class AsymmetricKey: Codable {
	/// Padding to be used for cryptographic operations applying this key.
	fileprivate static let signaturePadding: SecPadding = [], encryptionPadding: SecPadding = [] // .PKCS1SHA256

	/// Which properties should be serialized; automatically read by ``Codable`` protocol.
	enum CodingKeys: String, CodingKey {
		case key, keyClass, type, size
	}

	/// Opaque container of the asymmetric key this class wraps around.
	fileprivate let key: SecKey

	/// Cryptographic property of `key`.
	public let keyClass: CFString, type: CFString, size: Int

	/// See ``SecKeyGetBlockSize(_:)``.
	public var blockSize: Int { return SecKeyGetBlockSize(key) }

	/// Obtains the binary representation of this key.
	///
	/// Should only be used for public keys, since private keys should remain in the keychain.
	///
	/// - Returns: The mathematical representation of the key in binary Format. See ``SecKeyCopyExternalRepresentation(_:_:)`` for more information.
	///
	/// - Throws: An `NSError` if the key is not exportable.
	public func externalRepresentation() throws -> Data {
		if #available(macOS 10.12.1, iOS 10.0, *) {
			var error: Unmanaged<CFError>?
			guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
			}
			return data
		} else {
			let temporaryTag = try generateRandomData(length: 4)
			let temporaryLabel = temporaryTag.base64EncodedString()

			defer {
				// always try to remove key from keychain
				do {
					try removeFromKeychain(tag: temporaryTag, keyType: type, keyClass: keyClass, size: size)
				} catch {
					// only log this
					print("[WRN] [KeychainWrapper] Removing temporary key from keychain failed: \(error)")
				}
			}
			
			return try addToKeychain(key: key, label: temporaryLabel, tag: temporaryTag, keyType: type, keyClass: keyClass, size: size)
		}
	}

	/// Parses `data` based on the key properties provided to this method.
	///
	/// - Throws: An `NSError` if `data` does not contain an appropriate representation of a key.
	fileprivate convenience init(from data: Data, type: CFString, size: Int, keyClass: CFString) throws {
		if #available(macOS 10.12.1, iOS 10.0, *) {
			let attributes: [CFString : Any] = [
				kSecAttrKeyType:       type,
				kSecAttrKeySizeInBits: size,
				kSecAttrKeyClass:      keyClass]

			var error: Unmanaged<CFError>?
			guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
			}

			self.init(key: key, type: type, keyClass: keyClass, size: size)
		} else {
			let tag = try generateRandomData(length: 4)
			let temporaryLabel = tag.base64EncodedString()

			// always try to remove key from keychain before we add it again
			try? removeFromKeychain(tag: tag, keyType: type, keyClass: keyClass, size: size)
			
			defer {
				// always try to remove key from keychain when we added it
				do {
					try removeFromKeychain(tag: tag, keyType: type, keyClass: keyClass, size: size)
				} catch {
					// only log this
					print("[WRN] [KeychainWrapper] Removing temporary key from keychain failed: \(error)")
				}
			}
			
			let addquery: [CFString: Any] = [
				kSecClass:              kSecClassKey,
				kSecAttrKeyType:        type,
				kSecAttrApplicationTag: tag,
				kSecAttrKeySizeInBits:  size,
				kSecValueData:          data,
				kSecAttrLabel:          temporaryLabel,
				kSecAttrKeyClass:       keyClass,
				kSecReturnRef:          NSNumber(value: true)]

			var item: CFTypeRef?
			try SecKey.check(status: SecItemAdd(addquery as CFDictionary, &item), localizedError: NSLocalizedString("Adding key data to keychain failed.", tableName: "AsymmetricCrypto", comment: "Writing raw key data to the keychain produced an error."))

			self.init(key: item as! SecKey, type: type, keyClass: keyClass, size: size)
		}
	}

	/// Sets the properties directly and does not validate them.
	fileprivate init(key: SecKey, type: CFString, keyClass: CFString, size: Int) {
		self.type = type
		self.size = size
		self.key = key
		self.keyClass = keyClass
	}

	/// Decodes the properties, but does not validate them.
	///
	/// - Throws: An `NSError` if the binary data is invalid.
	required public convenience init(from decoder: Decoder) throws {
		let values = try decoder.container(keyedBy: CodingKeys.self)
		try self.init(from: try values.decode(Data.self, forKey: .key),
			type: try values.decode(String.self, forKey: .type) as CFString,
			size: try values.decode(Int.self, forKey: .size),
			keyClass: try values.decode(String.self, forKey: .keyClass) as CFString)
	}

	/// Encodes the key properties and external representation.
	///
	/// - Throws: The error from ``externalRepresentation()``, if any.
	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		try container.encode(externalRepresentation(), forKey: .key)
		try container.encode(type as String, forKey: .type)
		try container.encode(size, forKey: .size)
		try container.encode(keyClass as String, forKey: .keyClass)
	}
}

/// Represents a public asymmetric key.
public class AsymmetricPublicKey: AsymmetricKey {
	/// Hides this initializer by making it `private`.
	private override init(key: SecKey, type: CFString, keyClass: CFString, size: Int) {
		// we need to override (all) the superclasses designated initializers to inherit its convenience initializers (and thus the Codable initializer we want)
		super.init(key: key, type: type, keyClass: kSecAttrKeyClassPublic, size: size)
	}

	/// Initializes  `AsymmetricKey` with `keyClass` `kSecAttrKeyClassPublic`.
	@available(*, deprecated, message: "init(from data: Data, type: CFString, size: Int) is deprecated in v1.1.0, use init(from data: Data, algorithm: AsymmetricAlgorithm, size: Int)")
	public convenience init(from data: Data, type: CFString, size: Int) throws {
		try self.init(from: data, type: type, size: size, keyClass: kSecAttrKeyClassPublic)
	}

	/// Initializes a public asymmetric key from an external representation.
	///
	/// > Note: Added in v1.1.0.
	public convenience init(from data: Data, algorithm: AsymmetricAlgorithm, size: Int) throws {
		try self.init(from: data, type: algorithm.keyType, size: size, keyClass: kSecAttrKeyClassPublic)
	}

	/// Initializes  `AsymmetricKey` with `keyClass` `kSecAttrKeyClassPublic`.
	fileprivate init(key: SecKey, type: CFString, size: Int) {
		super.init(key: key, type: type, keyClass: kSecAttrKeyClassPublic, size: size)
	}

	/// Checks the integrity of `message` by calculating, whether the `signature` was computed with the corresponding private key to this public key.
	///
	/// - Throws: An `NSError` if the signature is invalid or the verification process failed.
	public func verify(message data: Data, signature: Data) throws {
		if #available(macOS 10.12.1, iOS 10.0, *) {
			let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
			guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
				let errorFormat = NSLocalizedString("Elliptic curve algorithm %@ does not support verifying.", tableName: "AsymmetricCrypto", comment: "Error description for verifying exception, which should never actually occur")

				let errorDescription = String(format: errorFormat, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256.rawValue as String)
				throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError, userInfo: [NSLocalizedDescriptionKey : errorDescription])
			}

			var error: Unmanaged<CFError>?
			guard SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, &error) else {
				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
			}
		} else {
			#if os(iOS)
				let digest = data.sha256()
				
				let status = signature.withUnsafePointer { (signatureBytes: UnsafePointer<UInt8>) in
					return digest.withUnsafePointer { (digestBytes: UnsafePointer<UInt8>) in
						SecKeyRawVerify(key, AsymmetricKey.signaturePadding, digestBytes, digest.count, signatureBytes, signature.count)
					}
				}
				
				try SecKey.check(status: status, localizedError: NSLocalizedString("Verifying signature failed.", tableName: "AsymmetricCrypto", comment: "Cryptographically verifying a message failed."))
			#else
				throw makeOldMacOSUnsupportedError()
			#endif
		}
	}

	/// Encrypts `message`, s.t. it can only be decrypted by the corresponding private key to this public key.
	///
	/// - Returns: Cipher text of `message`, which can be decrypted with ``AsymmetricPrivateKey/decrypt(message:)``.
	///
	/// - Throws: An `NSError` if the encryption process failed.
	public func encrypt(message plainText: Data) throws -> Data {
		if #available(macOS 10.12.1, iOS 10.0, *) {
			let algorithm = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM // does not work: ecdhKeyExchangeStandardX963SHA256, ecdhKeyExchangeCofactor
			guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
				let errorFormat = NSLocalizedString("Elliptic curve algorithm %@ does not support encryption.", tableName: "AsymmetricCrypto", comment: "Error description for verifying exception, which should never actually occur")

				let errorDescription = String(format: errorFormat, algorithm.rawValue as String)
				throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError, userInfo: [NSLocalizedDescriptionKey : errorDescription])
			}
			
			let padding = 0 // TODO find out how much it is for ECDH
			guard plainText.count <= (SecKeyGetBlockSize(key)-padding) else {
				let errorFormat = NSLocalizedString("Plain text length (%d) exceeds block size %d", tableName: "AsymmetricCrypto", comment: "Exception when trying to encrypt too-big data.")

				let errorDescription = String(format: errorFormat, plainText.count, SecKeyGetBlockSize(key)-padding)
				throw NSError(domain: NSCocoaErrorDomain, code: NSValidationErrorMaximum, userInfo: [NSLocalizedDescriptionKey : errorDescription])
			}
			
			var error: Unmanaged<CFError>?
			guard let cipherText = SecKeyCreateEncryptedData(key, algorithm, plainText as CFData, &error) as Data? else {
				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
			}
			
			return cipherText
		} else {
			#if os(iOS)
				var cipherSize = SecKeyGetBlockSize(key)
				var cipher = Data(count: cipherSize)
				let status = cipher.withUnsafeMutablePointer { (cipherBytes: UnsafeMutablePointer<UInt8>) in
					return plainText.withUnsafePointer { ( plainTextBytes: UnsafePointer<UInt8>) in
						SecKeyEncrypt(key, AsymmetricKey.encryptionPadding, plainTextBytes, plainText.count, cipherBytes, &cipherSize)
					}
				}
				try SecKey.check(status: status, localizedError: NSLocalizedString("Cryptographically encrypting failed.", tableName: "AsymmetricCrypto", comment: "Cryptographically encrypting a message failed."))
				
				return cipher.subdata(in: 0..<cipherSize)
			#else
				throw makeOldMacOSUnsupportedError()
			#endif
		}
	}
}

/// Represents a private asymmetric key.
public class AsymmetricPrivateKey: AsymmetricKey {

	/// Hides this initializer by making it `private`.
	private override init(key: SecKey, type: CFString, keyClass: CFString, size: Int) {
		// we need to override (all) the superclasses designated initializers to inherit its convenience initializers (and thus the Codable initializer we want)
		super.init(key: key, type: type, keyClass: kSecAttrKeyClassPrivate, size: size)
	}

	/// Initializes  `AsymmetricKey` with `keyClass` `kSecAttrKeyClassPrivate`.
	@available(*, deprecated, message: "init(from data: Data, type: CFString, size: Int) is deprecated in v1.1.0, use init(from data: Data, algorithm: AsymmetricAlgorithm, size: Int)")
	public convenience init(from data: Data, type: CFString, size: Int) throws {
		try self.init(from: data, type: type, size: size, keyClass: kSecAttrKeyClassPrivate)
	}

	/// Initializes a private asymmetric key from an external representation.
	///
	/// > Note: Added in v1.1.0.
	public convenience init(from data: Data, algorithm: AsymmetricAlgorithm, size: Int) throws {
		try self.init(from: data, type: algorithm.keyType, size: size, keyClass: kSecAttrKeyClassPrivate)
	}

	/// Initializes  `AsymmetricKey` with `keyClass` `kSecAttrKeyClassPrivate`.
	fileprivate init(key: SecKey, type: CFString, size: Int) {
		super.init(key: key, type: type, keyClass: kSecAttrKeyClassPrivate, size: size)
	}

	/// Produces a digital signature for `message`, which can be used to verify its integrity.
	///
	/// - Returns: The digital signature of `message`, which can be checked with ``AsymmetricPublicKey/verify(message:signature:)``.
	///
	/// - Throws: An `NSError` if the sign process failed.
	public func sign(message data: Data) throws -> Data {
		if #available(macOS 10.12.1, iOS 10.0, *) {
			let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
			guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
				let errorFormat = NSLocalizedString("Elliptic curve algorithm %@ does not support signing.", tableName: "AsymmetricCrypto", comment: "Error description for signing exception, which should never actually occur")

				let errorDescription = String(format: errorFormat, algorithm.rawValue as String)
				throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError, userInfo: [NSLocalizedDescriptionKey : errorDescription])
			}
			
			var error: Unmanaged<CFError>?
			guard let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) as Data? else {
				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
			}
			
			return signature
		} else {
			#if os(iOS)
				let digest = data.sha256()
				
				var signatureSize = 256 // in CryptoExercise it is SecKeyGetBlockSize(key), but on the internet it's some magic number like this
				var signature = Data(count: signatureSize)
				
				let status = signature.withUnsafeMutablePointer { (signatureBytes: UnsafeMutablePointer<UInt8>) in
					return digest.withUnsafePointer { (digestBytes: UnsafePointer<UInt8>) in
						SecKeyRawSign(key, AsymmetricKey.signaturePadding, digestBytes /* CC_SHA256_DIGEST_LENGTH */, digest.count, signatureBytes, &signatureSize)
					}
				}
				
				try SecKey.check(status: status, localizedError: NSLocalizedString("Cryptographically signing failed.", tableName: "AsymmetricCrypto", comment: "Cryptographically signing a message failed."))
				
				return signature.subdata(in: 0..<signatureSize)
			#else
				throw makeOldMacOSUnsupportedError()
			#endif
		}
	}

	/// Produces plain text for encrypted `message`.
	///
	/// - Returns: The plain text of `message`, which was encrypted with ``AsymmetricPublicKey/encrypt(message:)``.
	///
	/// - Throws: An `NSError` if the decryption process failed.
	public func decrypt(message cipherText: Data) throws -> Data {
		if #available(macOS 10.12.1, iOS 10.0, *) {
			let algorithm = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
			guard SecKeyIsAlgorithmSupported(key, .decrypt, algorithm) else {
				let errorFormat = NSLocalizedString("Elliptic curve algorithm %@ does not support decryption.", tableName: "AsymmetricCrypto", comment: "Error description for decryption exception, which should never actually occur")

				let errorDescription = String(format: errorFormat, algorithm.rawValue as String)
				throw NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError, userInfo: [NSLocalizedDescriptionKey : errorDescription])
			}
			
			var error: Unmanaged<CFError>?
			guard let clearText = SecKeyCreateDecryptedData(key, algorithm, cipherText as CFData, &error) as Data? else {
				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
			}
			
			return clearText
		} else {
			#if os(iOS)
				var plainTextSize = cipherText.count
				var plainText = Data(count: plainTextSize)
				let status = cipherText.withUnsafePointer { (cipherTextBytes: UnsafePointer<UInt8>) in
					return plainText.withUnsafeMutablePointer { (plainTextBytes: UnsafeMutablePointer<UInt8>) in
						SecKeyDecrypt(key, AsymmetricKey.encryptionPadding, cipherTextBytes, cipherText.count, plainTextBytes, &plainTextSize)
					}
				}
			try SecKey.check(status: status, localizedError: NSLocalizedString("Decrypting cipher text failed.", tableName: "AsymmetricCrypto", comment: "Cryptographically decrypting a message failed."))
				
				return plainText.subdata(in: 0..<plainTextSize)
			#else
				throw makeOldMacOSUnsupportedError()
			#endif
		}
	}
	
}

/// Container for an asymmetric key pair.
public struct KeyPair {
	/// Private part of this key pair, which needs to be kept secure.
	private let privateKey: AsymmetricPrivateKey

	/// Public part of this key pair, which can be passed around publicly.
	public let publicKey: AsymmetricPublicKey

	/// Keychain item property.
	let privateTag: Data, publicTag: Data, label: String

	/// The block size of the private key.
	public var blockSize: Int { return privateKey.blockSize }

	/// Generates a key pair and optionally stores it in the keychain.
	///
	/// > Note: Added in v1.1.0.
	@available(OSX 10.15, iOS 13.0, *)
	public init(privateTag: Data, publicTag: Data, algorithm: AsymmetricAlgorithm, size: Int, persistent: Bool, useEnclave: Bool = false) throws {
		self.privateTag = privateTag
		self.publicTag = publicTag

		// the label does not belong to the primary key, so we should be safe to ignore it
		self.label = ""

		let (publicKeyItem, privateKeyItem) = try generateAsymmetricKeyPair(privateTag: privateTag, publicTag: publicTag, algorithm: algorithm, size: size, persistent: persistent, useEnclave: useEnclave)

		self.privateKey = AsymmetricPrivateKey(key: privateKeyItem, type: algorithm.keyType, size: size)
		self.publicKey = AsymmetricPublicKey(key: publicKeyItem, type: algorithm.keyType, size: size)
	}

	/// Generates a key pair and optionally stores it in the keychain.
	@available(*, deprecated, message: "init with `label` attribute is deprecated in v1.1.0, use new init. But be careful on macOS: it will not reference the same key!")
	public init(label: String, privateTag: Data, publicTag: Data, type: CFString, size: Int, persistent: Bool, useEnclave: Bool = false) throws {
		// The documentation says: For key items, the primary keys include kSecAttrKeyClass, kSecAttrKeyType, kSecAttrApplicationLabel, kSecAttrApplicationTag, kSecAttrKeySizeInBits, and kSecAttrEffectiveKeySize.
		// - However, on kSecAttrApplicationLabel: […] for keys of class kSecAttrKeyClassPublic and kSecAttrKeyClassPrivate, the value of this attribute is the hash of the public key.
		// - kSecAttrKeyClass is implicit.
		// - kSecAttrEffectiveKeySize is listed in chapter 'Optional' …

		self.privateTag = privateTag
		self.publicTag = publicTag
		self.label = label

		var attributes: [CFString : Any]
		if useEnclave {
			var error: Unmanaged<CFError>?
			guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) else {
				throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
			}

			attributes = [
				kSecAttrLabel:         label,
				kSecAttrKeyType:       type,
				kSecAttrKeySizeInBits: size,
				kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
				kSecPrivateKeyAttrs: [
					kSecAttrIsPermanent:    persistent,
					kSecAttrApplicationTag: privateTag,
					kSecAttrAccessControl:  access
					] as CFDictionary,
				kSecPublicKeyAttrs: [
					kSecAttrIsPermanent:    persistent,
					kSecAttrApplicationTag: publicTag,
					kSecAttrAccessControl:  access
					] as CFDictionary
			]
		} else {
			attributes = [
				kSecAttrLabel:         label,
				kSecAttrKeyType:       type,
				kSecAttrKeySizeInBits: size,
				kSecAttrIsExtractable: false,
				kSecPrivateKeyAttrs: [
					kSecAttrIsPermanent:    persistent,
					kSecAttrApplicationTag: privateTag
					] as CFDictionary,
				kSecPublicKeyAttrs: [
					kSecAttrIsPermanent:    persistent,
					kSecAttrApplicationTag: publicTag
					] as CFDictionary
			]
		}
		
		var _publicKey, _privateKey: SecKey?
		try SecKey.check(status: SecKeyGeneratePair(attributes as CFDictionary, &_publicKey, &_privateKey), localizedError: NSLocalizedString("Generating cryptographic key pair failed.", tableName: "AsymmetricCrypto", comment: "Low level crypto error."))
		
		privateKey = AsymmetricPrivateKey(key: _privateKey!, type: type, size: size)
		publicKey = AsymmetricPublicKey(key: _publicKey!, type: type, size: size)
	}

	/// Loads a key pair from the system keychain.
	///
	/// > Note: Added in v1.1.0.
	@available(OSX 10.15, iOS 13.0, *)
	public init(fromKeychainWithPrivateTag privateTag: Data, publicTag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws {
		self.privateTag = privateTag
		self.publicTag = publicTag

		// the label does not belong to the primary key, so we should be safe to ignore it
		self.label = ""

		let privateKeyItem = try privateKeyFromKeychain(tag: privateTag, algorithm: algorithm, size: size)
		let publicKeyItem = try publicKeyFromKeychain(tag: publicTag, algorithm: algorithm, size: size)

		self.privateKey = AsymmetricPrivateKey(key: privateKeyItem, type: algorithm.keyType, size: size)
		self.publicKey = AsymmetricPublicKey(key: publicKeyItem, type: algorithm.keyType, size: size)
	}

	/// Loads a key pair from the system keychain.
	@available(*, deprecated, message: "init with `label` attribute is deprecated in v1.1.0, use new init. But be careful on macOS: it will not reference the same key!")
	public init(fromKeychainWith label: String, privateTag: Data, publicTag: Data, type: CFString, size: Int) throws {
		self.privateTag = privateTag
		self.publicTag = publicTag
		self.label = label
		privateKey = try privateKeyFromKeychain(label: label, tag: privateTag, type: type, size: size)
		#if ((arch(i386) || arch(x86_64)) && os(iOS)) || os(macOS) // iPhone Simulator or macOS
			publicKey = try publicKeyFromKeychain(label: label, tag: publicTag, type: type, size: size)
		#else
		if #available(iOS 10.0, *) {
			guard let pubKey = SecKeyCopyPublicKey(privateKey.key) else {
				throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInvalidAttributePrivateKeyFormat), userInfo: [NSLocalizedDescriptionKey : NSLocalizedString("No public key derivable.", tableName: "AsymmetricCrypto", comment: "Low level error.")])
			}
			publicKey = AsymmetricPublicKey(key: pubKey, type: type, size: size)
		} else {
			publicKey = try publicKeyFromKeychain(label: label, tag: publicTag, type: type, size: size)
		}
		#endif
	}

	/// Deletes the keys in the keychain.
	public func removeFromKeychain() throws {
		// it is not so critical when the public key remains, but more critical when the private one remains
		try? KeychainWrapper.removeFromKeychain(key: publicKey, label: label, tag: publicTag)
		try KeychainWrapper.removeFromKeychain(key: privateKey, label: label, tag: privateTag)
	}

	/// Obtains the binary representation of the public key, s.t. it can be distributed.
	public func externalPublicKey() throws -> Data {
		return try publicKey.externalRepresentation()
	}

	/// Signs `message` using the private key; see also ``AsymmetricPrivateKey/sign(message:)``.
	public func sign(message: Data) throws -> Data {
		return try privateKey.sign(message: message)
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
		return try privateKey.decrypt(message: cipherText)
	}
}

/// Wrapper-function around addToKeychain() for `SecKey`.
///
/// > Note: Added in v1.1.0.
@available(*, deprecated, message: "addToKeychain is deprecated in v1.1.0, use addAsymmetricKeyToKeychain")
func addToKeychain(key: AsymmetricKey, label: String, tag: Data) throws -> Data {
	return try addToKeychain(key: key.key, label: label, tag: tag, keyType: key.type, keyClass: key.keyClass, size: key.size)
}

/// Wrapper-function around removeFromKeychain() for `SecKey`.
///
/// > Note: Added in v1.1.0.
@available(*, deprecated, message: "removeFromKeychain is deprecated in v1.1.0, use removeAsymmetricKeyFromKeychain")
func removeFromKeychain(key: AsymmetricKey, label: String, tag: Data) throws {
	try removeFromKeychain(tag: tag, keyType: key.type, keyClass: key.keyClass, size: key.size)
}

/// Wrapper-function around keyFromKeychain() for `SecKey`.
///
/// > Note: Added in v1.1.0.
@available(*, deprecated, message: "publicKeyFromKeychain is deprecated in v1.1.0, use publicAsymmetricKeyFromKeychain")
func publicKeyFromKeychain(label: String, tag: Data, type: CFString, size: Int) throws -> AsymmetricPublicKey {
	let key = try keyFromKeychain(label: label, tag: tag, keyType: type, keyClass: kSecAttrKeyClassPublic, size: size)
	return AsymmetricPublicKey(key: key, type: type, size: size)
}

/// Wrapper-function around keyFromKeychain() for `SecKey`.
///
/// > Note: Added in v1.1.0.
@available(*, deprecated, message: "privateKeyFromKeychain is deprecated in v1.1.0, use privateAsymmetricKeyFromKeychain")
func privateKeyFromKeychain(label: String, tag: Data, type: CFString, size: Int) throws -> AsymmetricPrivateKey {
	let key = try keyFromKeychain(label: label, tag: tag, keyType: type, keyClass: kSecAttrKeyClassPrivate, size: size)
	return AsymmetricPrivateKey(key: key, type: type, size: size)
}

/// Insert an ``AsymmetricKey`` into the system's keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
func addAsymmetricKeyToKeychain(key: AsymmetricKey, tag: Data) throws -> Data {
	return try addAsymmetricKeyToKeychain(key: key.key, tag: tag, keyType: key.type, keyClass: key.keyClass, size: key.size)
}

/// Delete an ``AsymmetricKey`` from the system's keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
func removeAsymmetricKeyFromKeychain(key: AsymmetricKey, tag: Data) throws {
	try removeAsymmetricKeyFromKeychain(tag: tag, keyType: key.type, keyClass: key.keyClass, size: key.size)
}

/// Get an ``AsymmetricPublicKey`` from the system's keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
func publicAsymmetricKeyFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> AsymmetricPublicKey {
	let key = try publicKeyFromKeychain(tag: tag, algorithm: algorithm, size: size)
	return AsymmetricPublicKey(key: key, type: algorithm.keyType, size: size)
}

/// Get an ``AsymmetricPrivateKey`` from the system's keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
func privateAsymmetricKeyFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> AsymmetricPrivateKey {
	let key = try privateKeyFromKeychain(tag: tag, algorithm: algorithm, size: size)
	return AsymmetricPrivateKey(key: key, type: algorithm.keyType, size: size)
}

// MARK: - Private

/// Creates an error indicating that macOS below 10.12.1 is not supported.
private func makeOldMacOSUnsupportedError() -> Error {
	return NSError(domain: ErrorDomain, code: NSFeatureUnsupportedError, userInfo: [NSLocalizedDescriptionKey : NSLocalizedString("macOS below 10.12.1 is not supported.", tableName: "AsymmetricCrypto", comment: "Error description for cryptographic operation failure")])
}

