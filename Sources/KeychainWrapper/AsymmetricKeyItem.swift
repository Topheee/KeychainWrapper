//
//  AsymmetricKeyItem.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 14.11.2022.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

// MARK: Asymmetric Key Item Attributes

/// Algorithm of an asymmetric key.
///
/// Technical note: This is the selector for the `kSecAttrKeyType`.
///
/// > Note: Added in v1.1.0.
public enum AsymmetricAlgorithm: Sendable, Codable {
	case ec, rsa

	/// The value for the `kSecAttrKeyType` key.
	var keyType: CFString {
		switch self {
		case .ec:
			return kSecAttrKeyTypeECSECPrimeRandom
		case .rsa:
			return kSecAttrKeyTypeRSA
		}
	}
}

/// Part of an asymmetric key pair.
///
/// Technical note: This is the selector for the `kSecAttrKeyClass`.
///
/// > Note: Added in v2.0.0.
public enum AsymmetricKeyPart: Sendable, Codable {
	case privateKey, publicKey

	/// The value for the `kSecAttrKeyClass` key.
	var keyClass: CFString {
		switch self {
		case .privateKey:
			return kSecAttrKeyClassPrivate
		case .publicKey:
			return kSecAttrKeyClassPublic
		}
	}
}



// MARK: Key Item Generation

/// Generates a key pair and optionally stores it in the keychain.
///
/// - Parameters:
///   - privateKeyTag: The identifier of the key in the keychain. Corresponds to `kSecAttrApplicationTag`.
///   - algorithm: The algorithm of this key. Corresponds to `kSecAttrKeyType`.
///   - size: The size of this key. Corresponds to `kSecAttrKeySizeInBits`.
///   - useEnclave: Whether this key is only available if the device is unlocked. Corresponds to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
/// - Returns: First the public key and second the private key.
///
/// > Note: Added in v3.0.0.
@available(OSX 10.15, iOS 13.0, *)
public func generateAsymmetricPrivateKey(
	privateKeyTag: Data, algorithm: AsymmetricAlgorithm, size: Int,
	useEnclave: Bool = false)
throws -> SecKey {
	var attributes: [CFString : Any] = [
		kSecAttrLabel:         KeyItemLabelAttribute,
		kSecAttrKeyType:       algorithm.keyType,
		kSecAttrKeySizeInBits: size]

#if COMPILE_TEST
#else
	attributes[kSecUseDataProtectionKeychain] = true
#endif

	if useEnclave {
		var error: Unmanaged<CFError>?
		guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) else {
			throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
		}

		attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
		attributes[kSecPrivateKeyAttrs] = [
			kSecAttrIsPermanent:    true,
			kSecAttrApplicationTag: privateKeyTag,
			kSecAttrAccessControl:  access
			] as CFDictionary
	} else {
		attributes[kSecAttrIsExtractable] = false
		attributes[kSecPrivateKeyAttrs] = [
			kSecAttrIsPermanent:    true,
			kSecAttrApplicationTag: privateKeyTag
			] as CFDictionary
	}

	var error: Unmanaged<CFError>?
	guard let privateKey = SecKeyCreateRandomKey(
		attributes as CFDictionary, &error) else {
		throw (error?.takeRetainedValue() as? Error) ?? makeFatalError()
	}

	return privateKey
}

// MARK: Key Item Retrieval

/// Extracts an asymmetric cryptographic key from the system's Keychain.
///
/// > Note: Added in v2.0.0.
public func asymmetricKeyFromKeychain(tag: Data, part: AsymmetricKeyPart,
									  algorithm: AsymmetricAlgorithm,
									  size: Int) throws -> SecKey {
	var query = baseKeychainQuery(keyClass: part.keyClass, tag: tag,
								  algorithm: algorithm, size: size)
	query[kSecReturnRef] = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading key from keychain failed.",
										  tableName: "KeychainAccess",
			bundle: .module,
			comment: "Attempt to read a keychain item failed."))

	return item as! SecKey
}

/// Extracts an encoded asymmetric cryptographic key from the system's Keychain.
///
/// > Note: Added in v2.0.0.
public func asymmetricKeyDataFromKeychain(tag: Data, part: AsymmetricKeyPart,
										  algorithm: AsymmetricAlgorithm,
										  size: Int) throws -> Data {
	var query = baseKeychainQuery(keyClass: part.keyClass, tag: tag,
								  algorithm: algorithm, size: size)
	query[kSecReturnData] = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading key data from keychain failed.",
										  tableName: "KeychainAccess",
			bundle: .module,
			comment: "Attempt to read a keychain item failed."))

	return (item as! CFData) as Data
}

// MARK: Key Item Insertion

/// Inserts a cryptographic key into the system's Keychain.
///
/// > Note: Added in v2.0.0.
@discardableResult
public func addAsymmetricKeyToKeychain(_ key: SecKey, tag: Data,
									   part: AsymmetricKeyPart,
									   algorithm: AsymmetricAlgorithm,
									   size: Int) throws -> Data {
	var query = baseKeychainQuery(keyClass: part.keyClass, tag: tag,
								  algorithm: algorithm, size: size)
	query[kSecValueRef]   = key
	query[kSecReturnData] = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemAdd(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Adding key data to keychain failed.",
										  tableName: "KeychainAccess",
			bundle: .module,
			comment: "Writing raw key data to the keychain produced an error."))

	return (item as! CFData) as Data
}

// MARK: Key Item Deletion

/// Purges a cryptographic key from the system's Keychain.
///
/// > Note: Added in v2.0.0.
public func removeAsymmetricKeyFromKeychain(tag: Data,
											part: AsymmetricKeyPart,
											algorithm: AsymmetricAlgorithm,
											size: Int) throws {
	let query = baseKeychainQuery(keyClass: part.keyClass, tag: tag,
								  algorithm: algorithm, size: size)

	try SecKey.check(status: SecItemDelete(query as CFDictionary),
		localizedError: NSLocalizedString("Deleting keychain item failed.",
										  tableName: "KeychainAccess",
			bundle: .module,
			comment: "Removing an item from the keychain produced an error."))
}

// MARK: - Private

/// User-visible label for key items.
///
/// > Note: Added in v1.1.0.
private let KeyItemLabelAttribute = "KeychainWrapper Key Item"

/// Produces the query parameters with all primary key attributes for asymmetric key items.
@available(OSX 10.15, iOS 13.0, *)
private func baseKeychainQuery(keyClass: CFString, tag: Data,
							   algorithm: AsymmetricAlgorithm,
							   size: Int) -> [CFString: Any] {
	// For key items, the primary keys include kSecAttrKeyClass,
	// kSecAttrKeyType, kSecAttrApplicationLabel, kSecAttrApplicationTag,
	// kSecAttrKeySizeInBits, and kSecAttrEffectiveKeySize.
	// However, for asymmetric keys kSecAttrApplicationLabel is derived from
	// the hash of the public key and symmetric keys are not really supported:
	// https://stackoverflow.com/questions/22172229/how-to-use-secitemadd-to-store-a-symmetric-key-in-os-x
	// kSecAttrEffectiveKeySize is automatically set depended on
	// kSecAttrKeyType and kSecAttrKeySizeInBits.

	var query: [CFString : Any] = [
		kSecClass:              kSecClassKey,
		kSecAttrLabel:          KeyItemLabelAttribute,
		kSecAttrKeyClass:       keyClass,
		kSecAttrKeySizeInBits:  size,
		kSecAttrApplicationTag: tag,
		kSecAttrKeyType:        algorithm.keyType]

#if COMPILE_TEST
#else
	query[kSecUseDataProtectionKeychain] = true
#endif

	return query
}
