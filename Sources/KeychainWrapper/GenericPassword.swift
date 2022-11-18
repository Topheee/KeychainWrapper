//
//  GenericPassword.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 13.11.2022.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

/// Writes a generic UTF-8 encoded secret, overwriting a possible previous value.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func persistGenericPasswordInKeychain(_ password: String, account: String, service: String, encoding: String.Encoding) throws {
	guard let data = password.data(using: encoding) else { throw makeStringEncodingError() }

	try persistGenericPasswordInKeychain(data, account: account, service: service)
}

/// Writes a generic secret, overwriting a possible previous value.
///
/// `account` and `service` together identify the secret, so you must pass the same value combination to the other generic password functions.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func persistGenericPasswordInKeychain(_ password: Data, account: String, service: String) throws {
	// Delete old password first (if available).
	try? removeGenericPasswordFromKeychain(account: account, service: service)

	var query = baseKeychainQuery(account: account, service: service)
	query[kSecAttrLabel]       = GenericPasswordLabelAttribute
	query[kSecAttrDescription] = KeychainWrapperDescriptionAttribute
	query[kSecAttrComment]     = KeychainWrapperCommentAttribute
	query[kSecValueData]       = password

	try SecKey.check(status: SecItemAdd(query as CFDictionary, nil), localizedError: NSLocalizedString("Adding generic password to keychain failed.", tableName: "KeychainAccess", comment: "SecItemAdd failed"))
}

/// Retrieves a generic UTF-8 encoded secret from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func genericPasswordFromKeychain(account: String, service: String, encoding: String.Encoding) throws -> String {
	let passwordData: Data = try genericPasswordFromKeychain(account: account, service: service)

	guard let password = String(data: passwordData, encoding: encoding) else {
		throw makeStringDecodingError()
	}

	return password
}

/// Retrieves a generic secret from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func genericPasswordFromKeychain(account: String, service: String) throws -> Data {
	var query = baseKeychainQuery(account: account, service: service)
	query[kSecMatchLimit] = kSecMatchLimitOne
	query[kSecReturnData] = true

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading generic password from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	guard let passwordData = item as? Data else {
		throw makeFatalError()
	}

	return passwordData
}

/// Purges a generic secret from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func removeGenericPasswordFromKeychain(account: String, service: String) throws {
	try SecKey.check(status: SecItemDelete(baseKeychainQuery(account: account, service: service) as CFDictionary),
		localizedError: NSLocalizedString("Deleting generic password from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to delete a keychain item failed."))
}

// MARK: - Private

/// User-visible label for generic passwords.
///
/// > Note: Added in v1.1.0.
private let GenericPasswordLabelAttribute = "KeychainWrapper Generic Password"

/// Produces the query parameters with all primary key attributes for generic passwords.
@available(OSX 10.15, iOS 13.0, *)
private func baseKeychainQuery(account: String, service: String) -> [CFString: Any] {
	var query: [CFString : Any] = [
		kSecClass:       kSecClassGenericPassword,
		kSecAttrService: service,
		kSecAttrAccount: account]

#if COMPILE_TEST
#else
	query[kSecUseDataProtectionKeychain] = true
#endif

	return query
}
