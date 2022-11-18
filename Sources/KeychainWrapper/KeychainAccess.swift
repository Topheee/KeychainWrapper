//
//  KeychainAccess.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 06.10.22.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

/// Extracts a cryptographic key from the system's Keychain.
@available(*, deprecated, message: "keyFromKeychain is deprecated in v1.1.0, use privateKeyFromKeychain, publicKeyFromKeychain, or symmetricKeyFromKeychain")
public func keyFromKeychain(label: String, tag: Data, keyType: CFString, keyClass: CFString, size: Int) throws -> SecKey {
	let getquery: [CFString : Any] = [
		kSecAttrLabel:          label,
		kSecClass:              kSecClassKey,
		kSecAttrKeyClass:       keyClass,
		kSecAttrKeyType:        keyType,
		kSecAttrKeySizeInBits:  size,
		kSecAttrApplicationTag: tag,
		kSecReturnRef:          NSNumber(value: true)]

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(getquery as CFDictionary, &item), localizedError: NSLocalizedString("Reading key from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	return item as! SecKey
}

/// Extracts an encoded cryptographic key from the system's Keychain.
@available(*, deprecated, message: "keyDataFromKeychain is deprecated in v1.1.0, use privateKeyDataFromKeychain, publicKeyDataFromKeychain, or symmetricKeyDataFromKeychain")
public func keyDataFromKeychain(label: String, tag: Data, keyType: CFString, keyClass: CFString, size: Int) throws -> Data {
	let getquery: [CFString : Any] = [
		kSecAttrLabel:          label,
		kSecClass:              kSecClassKey,
		kSecAttrKeyClass:       keyClass,
		kSecAttrKeySizeInBits:  size,
		kSecAttrApplicationTag: tag,
		kSecAttrKeyType:        keyType,
		kSecReturnData:         NSNumber(value: true)]

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(getquery as CFDictionary, &item), localizedError: NSLocalizedString("Reading key data from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	return (item as! CFData) as Data
}

/// Inserts a cryptographic key into the system's Keychain.
@available(*, deprecated, message: "addToKeychain is deprecated in v1.1.0, use addPrivateKeyToKeychain, addPublicKeyToKeychain, or addSymmetricKeyToKeychain")
public func addToKeychain(key: SecKey, label: String, tag: Data, keyType: CFString, keyClass: CFString, size: Int) throws -> Data {
	let addquery: [CFString : Any]
	if #available(OSX 10.15, iOS 13.0, *) {
		addquery = [
			kSecAttrLabel:                 label,
			kSecUseDataProtectionKeychain: true,
			kSecClass:                     kSecClassKey,
			kSecAttrKeyClass:              keyClass,
			kSecValueRef:                  key,
			kSecAttrKeySizeInBits:         size,
			kSecAttrApplicationTag:        tag,
			kSecAttrKeyType:               keyType,
			kSecReturnData:                NSNumber(value: true)]
	} else {
		addquery = [
			kSecAttrLabel:          label,
			kSecClass:              kSecClassKey,
			kSecAttrKeyClass:       keyClass,
			kSecValueRef:           key,
			kSecAttrKeySizeInBits:  size,
			kSecAttrApplicationTag: tag,
			kSecAttrKeyType:        keyType,
			kSecReturnData:         NSNumber(value: true)]
	}

	var item: CFTypeRef?
	try SecKey.check(status: SecItemAdd(addquery as CFDictionary, &item), localizedError: NSLocalizedString("Adding key data to keychain failed.", tableName: "KeychainAccess", comment: "Writing raw key data to the keychain produced an error."))

	return (item as! CFData) as Data
}

/// Purges a cryptographic key from the system's Keychain.
@available(*, deprecated, message: "removeFromKeychain is deprecated in v1.1.0, use removePrivateKeyFromKeychain, removePublicKeyFromKeychain, or removeSymmetricKeyFromKeychain")
public func removeFromKeychain(tag: Data, keyType: CFString, keyClass: CFString, size: Int) throws {
	let remquery: [CFString : Any] = [
		kSecClass:              kSecClassKey,
		kSecAttrKeyClass:       keyClass,
		kSecAttrKeySizeInBits:  size,
		kSecAttrApplicationTag: tag,
		kSecAttrKeyType:        keyType]

	try SecKey.check(status: SecItemDelete(remquery as CFDictionary), localizedError: NSLocalizedString("Deleting keychain item failed.", tableName: "KeychainAccess", comment: "Removing an item from the keychain produced an error."))
}

/// Writes a generic unspecified secret, overwriting a possible previous value.
@available(*, deprecated, message: "persistSecretInKeychain is deprecated in v1.1.0, use persistGenericPasswordInKeychain")
public func persistSecretInKeychain(secret: String, label: String) throws {
	guard let tokenData = secret.data(using: .utf8) else { throw makeEmptyKeychainDataError() }

	// Delete old token first (if available).
	try? removeSecretFromKeychain(label: label)

	let query: [CFString : Any] = [
		kSecClass:           kSecClassGenericPassword,
		kSecAttrLabel:       label,
		kSecValueData:       tokenData]

	try SecKey.check(status: SecItemAdd(query as CFDictionary, nil), localizedError: NSLocalizedString("Adding secret to keychain failed.", tableName: "KeychainAccess", comment: "SecItemAdd failed"))
}

/// Retrieves a generic unspecified secret from the keychain.
@available(*, deprecated, message: "secretFromKeychain is deprecated in v1.1.0, use genericPasswordFromKeychain")
public func secretFromKeychain(label: String) throws -> String {
	let query: [CFString : Any] = [
		kSecClass:           kSecClassGenericPassword,
		kSecAttrLabel:       label,
		kSecMatchLimit:      kSecMatchLimitOne,
		kSecReturnData:      true]

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item), localizedError: NSLocalizedString("Reading generic secret from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	guard let passwordData = item as? Data,
		  let password = String(data: passwordData, encoding: String.Encoding.utf8) else {
		throw makeEmptyKeychainDataError()
	}

	return password
}

/// Purges a generic unspecified secret from the keychain.
@available(*, deprecated, message: "removeSecretFromKeychain is deprecated in v1.1.0, use removeGenericPasswordFromKeychain")
public func removeSecretFromKeychain(label: String) throws {
#if os(macOS)
	// optimization for macOS
	// does not work on iOS, since specifying `kSecMatchLimit` there results in an 'One or more parameters passed to a function were not valid.' error
	let query: [CFString : Any] = [
		kSecClass:           kSecClassGenericPassword,
		kSecAttrLabel:       label,
		kSecMatchLimit:      kSecMatchLimitAll]

	try SecKey.check(status: SecItemDelete(query as CFDictionary), localizedError: NSLocalizedString("Deleting secret from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to delete a keychain item failed."))
#else
	let query: [CFString : Any] = [
		kSecClass:               kSecClassGenericPassword,
		kSecAttrLabel:           label,
		kSecMatchLimit:          kSecMatchLimitAll,
		kSecReturnPersistentRef: true]

	var itemArray: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &itemArray), localizedError: NSLocalizedString("Reading generic secret from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	if let items = itemArray as? [Data] {
		try items.forEach {
			let query: [CFString : Any] = [kSecValuePersistentRef: $0]
			try SecKey.check(status: SecItemDelete(query as CFDictionary), localizedError: NSLocalizedString("Deleting keychain item failed.", tableName: "KeychainAccess", comment: "Removing an item from the keychain produced an error."))
		}
	} else {
		throw makeFatalError()
	}
#endif
}

/// Writes the `password` into the keychain as an internet password.
@available(*, deprecated, message: "persistInternetPasswordInKeychain(_:,_:,_:) is deprecated in v1.1.0, use one of the new unambiguous persistInternetPasswordInKeychain alternatives")
public func persistInternetPasswordInKeychain(account: String, url: URL, _ password: Data) throws {
	let query: [CFString : Any] = [
		kSecClass:       kSecClassInternetPassword,
		kSecAttrAccount: account,
		kSecAttrServer:  url.absoluteString,
		kSecValueData:   password]

	try SecKey.check(status: SecItemAdd(query as CFDictionary, nil), localizedError: NSLocalizedString("Adding internet password to keychain failed.", tableName: "KeychainAccess", comment: "SecItemAdd failed"))
}

/// Retrieves an internet password from the keychain.
@available(*, deprecated, message: "internetPasswordFromKeychain(_:,_:) is deprecated in v1.1.0, use one of the new unambiguous internetPasswordFromKeychain alternatives")
public func internetPasswordFromKeychain(account: String, url: URL) throws -> String {
	let query: [CFString : Any] = [
		kSecClass:       kSecClassInternetPassword,
		kSecAttrServer:  url.absoluteString,
		kSecAttrAccount: account,
		kSecMatchLimit:  kSecMatchLimitOne,
		kSecReturnData:  true]

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item), localizedError: NSLocalizedString("Reading internet password from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	guard let passwordData = item as? Data,
		  let password = String(data: passwordData, encoding: String.Encoding.utf8) else {
		throw makeEmptyKeychainDataError()
	}

	return password
}

/// Purges an internet password from the keychain.
@available(*, deprecated, message: "removeInternetPasswordFromKeychain(_:,_:) is deprecated in v1.1.0, use one of the new unambiguous removeInternetPasswordFromKeychain alternatives")
public func removeInternetPasswordFromKeychain(account: String, url: URL) throws {
	let query: [CFString : Any] = [
		kSecClass:       kSecClassInternetPassword,
		kSecAttrAccount: account,
		kSecAttrServer:  url.absoluteString]

	try SecKey.check(status: SecItemDelete(query as CFDictionary), localizedError: NSLocalizedString("Deleting internet password from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to delete a keychain item failed."))
}
