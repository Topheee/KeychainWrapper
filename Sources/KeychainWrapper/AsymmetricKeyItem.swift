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
public enum AsymmetricAlgorithm {
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

// MARK: Key Item Generation

/// Generates a key pair and optionally stores it in the keychain.
///
/// - returns: First the public key and second the private key.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func generateAsymmetricKeyPair(privateTag: Data, publicTag: Data, algorithm: AsymmetricAlgorithm, size: Int, persistent: Bool, useEnclave: Bool = false) throws -> (SecKey, SecKey) {
	var attributes: [CFString : Any] = [
		kSecAttrLabel:         KeyItemLabelAttribute,
		kSecAttrDescription:   KeychainWrapperDescriptionAttribute,
		kSecAttrComment:       KeychainWrapperCommentAttribute,
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
			kSecAttrIsPermanent:    persistent,
			kSecAttrApplicationTag: privateTag,
			kSecAttrAccessControl:  access
			] as CFDictionary
		attributes[kSecPublicKeyAttrs] = [
			kSecAttrIsPermanent:    persistent,
			kSecAttrApplicationTag: publicTag,
			kSecAttrAccessControl:  access
			] as CFDictionary
	} else {
		attributes[kSecAttrIsExtractable] = false
		attributes[kSecPrivateKeyAttrs] = [
			kSecAttrIsPermanent:    persistent,
			kSecAttrApplicationTag: privateTag
			] as CFDictionary
		attributes[kSecPublicKeyAttrs] = [
			kSecAttrIsPermanent:    persistent,
			kSecAttrApplicationTag: publicTag
			] as CFDictionary
	}

	var publicKeyItem, privateKeyItem: SecKey?
	try SecKey.check(status: SecKeyGeneratePair(attributes as CFDictionary, &publicKeyItem, &privateKeyItem), localizedError: NSLocalizedString("Generating cryptographic key pair failed.", tableName: "AsymmetricCrypto", comment: "Low level crypto error."))

	guard let publicKey = publicKeyItem, let privateKey = privateKeyItem else {
		throw makeFatalError()
	}

	return (publicKey, privateKey)
}

// MARK: Key Item Retrieval

/// Extracts an asymmetric public cryptographic key from the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func publicKeyFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> SecKey {
	var query = baseKeychainQuery(keyClass: kSecAttrKeyClassPrivate, tag: tag, algorithm: algorithm, size: size)
	query[kSecReturnRef] = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading key from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	return item as! SecKey
}

/// Extracts an asymmetric private cryptographic key from the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func privateKeyFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> SecKey {
	var query = baseKeychainQuery(keyClass: kSecAttrKeyClassPrivate, tag: tag, algorithm: algorithm, size: size)
	query[kSecReturnRef] = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading key from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	return item as! SecKey
}

/// Extracts an encoded asymmetric public cryptographic key from the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func publicKeyDataFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> Data {
	var query = baseKeychainQuery(keyClass: kSecAttrKeyClassPrivate, tag: tag, algorithm: algorithm, size: size)
	query[kSecReturnData] = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading key data from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	return (item as! CFData) as Data
}

/// Extracts an encoded asymmetric private cryptographic key from the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func privateKeyDataFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> Data {
	var query = baseKeychainQuery(keyClass: kSecAttrKeyClassPrivate, tag: tag, algorithm: algorithm, size: size)
	query[kSecReturnData] = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading key data from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	return (item as! CFData) as Data
}

// MARK: Key Item Insertion

/// Inserts a cryptographic key into the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func addPublicKeyToKeychain(_ key: SecKey, tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> Data {
	var query = baseKeychainQuery(keyClass: kSecAttrKeyClassPublic, tag: tag, algorithm: algorithm, size: size)
	query[kSecAttrLabel]       = KeyItemLabelAttribute
	query[kSecAttrDescription] = KeychainWrapperDescriptionAttribute
	query[kSecAttrComment]     = KeychainWrapperCommentAttribute
	query[kSecValueRef]        = key
	query[kSecReturnData]      = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemAdd(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Adding key data to keychain failed.", tableName: "KeychainAccess", comment: "Writing raw key data to the keychain produced an error."))

	return (item as! CFData) as Data
}

/// Inserts a cryptographic key into the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func addPrivateKeyToKeychain(_ key: SecKey, tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws -> Data {
	var query = baseKeychainQuery(keyClass: kSecAttrKeyClassPrivate, tag: tag, algorithm: algorithm, size: size)
	query[kSecAttrLabel]       = KeyItemLabelAttribute
	query[kSecAttrDescription] = KeychainWrapperDescriptionAttribute
	query[kSecAttrComment]     = KeychainWrapperCommentAttribute
	query[kSecValueRef]        = key
	query[kSecReturnData]      = NSNumber(value: true)

	var item: CFTypeRef?
	try SecKey.check(status: SecItemAdd(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Adding key data to keychain failed.", tableName: "KeychainAccess", comment: "Writing raw key data to the keychain produced an error."))

	return (item as! CFData) as Data
}

// MARK: Key Item Deletion

/// Purges a cryptographic key from the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func removePublicKeyFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws {
	let query = baseKeychainQuery(keyClass: kSecAttrKeyClassPublic, tag: tag, algorithm: algorithm, size: size)

	try SecKey.check(status: SecItemDelete(query as CFDictionary),
		localizedError: NSLocalizedString("Deleting keychain item failed.", tableName: "KeychainAccess", comment: "Removing an item from the keychain produced an error."))
}

/// Purges a cryptographic key from the system's Keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func removePrivateKeyFromKeychain(tag: Data, algorithm: AsymmetricAlgorithm, size: Int) throws {
	let query = baseKeychainQuery(keyClass: kSecAttrKeyClassPrivate, tag: tag, algorithm: algorithm, size: size)

	try SecKey.check(status: SecItemDelete(query as CFDictionary),
		localizedError: NSLocalizedString("Deleting keychain item failed.", tableName: "KeychainAccess", comment: "Removing an item from the keychain produced an error."))
}

// MARK: - Private

/// User-visible label for key items.
///
/// > Note: Added in v1.1.0.
private let KeyItemLabelAttribute = "KeychainWrapper Key Item"

/// Produces the query parameters with all primary key attributes for asymmetric key items.
private func baseKeychainQuery(keyClass: CFString, tag: Data, algorithm: AsymmetricAlgorithm, size: Int) -> [CFString: Any] {
        // For key items, the primary keys include kSecAttrKeyClass, kSecAttrKeyType, kSecAttrApplicationLabel, kSecAttrApplicationTag, kSecAttrKeySizeInBits, and kSecAttrEffectiveKeySize.
	// However, for asymmetric keys kSecAttrApplicationLabel is derived from the hash of the public key and symmetric keys are not really supported: https://stackoverflow.com/questions/22172229/how-to-use-secitemadd-to-store-a-symmetric-key-in-os-x
	// kSecAttrEffectiveKeySize is automatically set depended on kSecAttrKeyType and kSecAttrKeySizeInBits.

        var query: [CFString : Any] = [
		kSecClass:              kSecClassKey,
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
