//
//  KeychainAccess.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 06.10.22.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

/// Denotes the values of [kSecAttrAuthenticationType](https://developer.apple.com/documentation/security/ksecattrauthenticationtype).
///
/// > Note: Added in v1.1.0.
public enum AuthenticationTypeKeychainAttribute {
	/// One of the Authentication Type Values.
	case `default`, ntlm, msn, dpa, rpa, httpBasic, httpDigest, htmlForm

	/// The value to include in the keychain query dictionaries for the `kSecAttrAuthenticationType` key.
	var queryValue: CFString {
		switch self {
		case .`default`:
			return kSecAttrAuthenticationTypeDefault
		case .ntlm:
			return kSecAttrAuthenticationTypeNTLM
		case .msn:
			return kSecAttrAuthenticationTypeMSN
		case .dpa:
			return kSecAttrAuthenticationTypeDPA
		case .rpa:
			return kSecAttrAuthenticationTypeRPA
		case .httpBasic:
			return kSecAttrAuthenticationTypeHTTPBasic
		case .httpDigest:
			return kSecAttrAuthenticationTypeHTTPDigest
		case .htmlForm:
			return kSecAttrAuthenticationTypeHTMLForm
		}
	}
}
/// Denotes the values of [kSecAttrProtocol](https://developer.apple.com/documentation/security/ksecattrprotocol).
///
/// > Note: Added in v1.1.0.
public enum ProtocolKeychainAttribute {
	/// One of the Protocol Values.
	case https

	/// Converts an `URL.scheme` property into a `ProtocolKeychainAttribute`.
	public static func fromScheme(_ scheme: String) -> ProtocolKeychainAttribute? {
		switch (scheme.lowercased()) {
		case "https":
			return .https
		default:
			return nil
		}
	}

	/// The value to include in the keychain query dictionaries for the `kSecAttrProtocol` key.
	var queryValue: CFString {
		switch self {
		case .https:
			return kSecAttrAuthenticationTypeDefault
		}
	}
}

/// Writes the `password` into the keychain as an internet password, for which the primary key is partly derived from `url`.
///
/// Note that the account is not derived from the `url.user` property, since it is so rarely used.
/// Note that `url.path` is made part of the primary key, so most of the time you want to strip the path from the `URL`.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func persistInternetPasswordInKeychain(_ password: String, account: String, securityDomain: String, url: URL, authenticationType: AuthenticationTypeKeychainAttribute = .`default`, encoding: String.Encoding) throws {
	guard let data = password.data(using: encoding) else { throw makeStringEncodingError() }

	try persistInternetPasswordInKeychain(data, account: account, securityDomain: securityDomain, url: url, authenticationType: authenticationType)
}

/// Writes the `password` into the keychain as an internet password, for which the primary key is partly derived from `url`.
///
/// Note that the account is not derived from the `url.user` property, since it is so rarely used.
/// Note that `url.path` is made part of the primary key, so most of the time you want to strip the path from the `URL`.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func persistInternetPasswordInKeychain(_ password: Data, account: String, securityDomain: String, url: URL, authenticationType: AuthenticationTypeKeychainAttribute = .`default`) throws {
	let pk = URLPrimaryKeyData.fromURL(url)
	try persistInternetPasswordInKeychain(password, account: account, securityDomain: securityDomain, server: pk.server, port: pk.port, path: pk.path, protocolAttribute: pk.protocolAttribute, authenticationType: authenticationType)
}

/// Writes the `password` into the keychain as an internet password.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func persistInternetPasswordInKeychain(_ password: String, account: String, securityDomain: String, server: String, port: Int, path: String, protocolAttribute: ProtocolKeychainAttribute, authenticationType: AuthenticationTypeKeychainAttribute = .`default`, encoding: String.Encoding) throws {
	guard let data = password.data(using: encoding) else { throw makeStringEncodingError() }

	try persistInternetPasswordInKeychain(data, account: account, securityDomain: securityDomain, server: server, port: port, path: path, protocolAttribute: protocolAttribute, authenticationType: authenticationType)
}

/// Writes the `password` into the keychain as an internet password.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func persistInternetPasswordInKeychain(_ password: Data, account: String, securityDomain: String, server: String, port: Int, path: String, protocolAttribute: ProtocolKeychainAttribute, authenticationType: AuthenticationTypeKeychainAttribute = .`default`) throws {
	var query = baseKeychainQuery(account: account, securityDomain: securityDomain, server: server, port: port, path: path, protocolAttribute: protocolAttribute, authenticationType: authenticationType)
	query[kSecAttrLabel]       = InternetPasswordLabelAttribute
	query[kSecAttrDescription] = KeychainWrapperDescriptionAttribute
	query[kSecAttrComment]     = KeychainWrapperCommentAttribute
	query[kSecValueData]       = password

	try SecKey.check(status: SecItemAdd(query as CFDictionary, nil),
		localizedError: NSLocalizedString("Adding internet password to keychain failed.", tableName: "KeychainAccess", comment: "SecItemAdd failed"))
}

/// Retrieves and decodes an internet password from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func internetPasswordFromKeychain(account: String, securityDomain: String, url: URL, authenticationType: AuthenticationTypeKeychainAttribute = .`default`, encoding: String.Encoding) throws -> String {
	let passwordData: Data = try internetPasswordFromKeychain(account: account, securityDomain: securityDomain, url: url, authenticationType: authenticationType)

	guard let password = String(data: passwordData, encoding: encoding) else {
		throw makeStringDecodingError()
	}

	return password
}

/// Retrieves an internet password from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func internetPasswordFromKeychain(account: String, securityDomain: String, url: URL, authenticationType: AuthenticationTypeKeychainAttribute = .`default`) throws -> Data {
	let pk = URLPrimaryKeyData.fromURL(url)
	return try internetPasswordFromKeychain(account: account, securityDomain: securityDomain, server: pk.server, port: pk.port, path: pk.path, protocolAttribute: pk.protocolAttribute, authenticationType: authenticationType)
}

/// Retrieves and decodes an internet password from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func internetPasswordFromKeychain(account: String, securityDomain: String, server: String, port: Int, path: String, protocolAttribute: ProtocolKeychainAttribute, authenticationType: AuthenticationTypeKeychainAttribute = .`default`, encoding: String.Encoding) throws -> String {
	let passwordData: Data = try internetPasswordFromKeychain(account: account, securityDomain: securityDomain, server: server, port: port, path: path, protocolAttribute: protocolAttribute, authenticationType: authenticationType)

	guard let password = String(data: passwordData, encoding: encoding) else {
		throw makeStringDecodingError()
	}

	return password
}

/// Retrieves an internet password from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func internetPasswordFromKeychain(account: String, securityDomain: String, server: String, port: Int, path: String, protocolAttribute: ProtocolKeychainAttribute, authenticationType: AuthenticationTypeKeychainAttribute = .`default`) throws -> Data {
	var query = baseKeychainQuery(account: account, securityDomain: securityDomain, server: server, port: port, path: path, protocolAttribute: protocolAttribute, authenticationType: authenticationType)
	query[kSecMatchLimit] = kSecMatchLimitOne
	query[kSecReturnData] = true

	var item: CFTypeRef?
	try SecKey.check(status: SecItemCopyMatching(query as CFDictionary, &item),
		localizedError: NSLocalizedString("Reading internet password from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to read a keychain item failed."))

	guard let passwordData = item as? Data else {
		throw makeEmptyKeychainDataError()
	}

	return passwordData
}

/// Purges an internet password from the keychain.
///
/// > Note: Added in v1.1.0.
@available(OSX 10.15, iOS 13.0, *)
public func removeInternetPasswordFromKeychain(account: String, securityDomain: String, url: URL, authenticationType: AuthenticationTypeKeychainAttribute = .`default`) throws {
	let pk = URLPrimaryKeyData.fromURL(url)
	try removeInternetPasswordFromKeychain(account: account, securityDomain: securityDomain, server: pk.server, port: pk.port, path: pk.path, protocolAttribute: pk.protocolAttribute, authenticationType: authenticationType)
}

/// Purges an internet password from the keychain.
@available(OSX 10.15, iOS 13.0, *)
public func removeInternetPasswordFromKeychain(account: String, securityDomain: String, server: String, port: Int, path: String, protocolAttribute: ProtocolKeychainAttribute, authenticationType: AuthenticationTypeKeychainAttribute = .`default`) throws {
	let query = baseKeychainQuery(account: account, securityDomain: securityDomain, server: server, port: port, path: path, protocolAttribute: protocolAttribute, authenticationType: authenticationType)

	try SecKey.check(status: SecItemDelete(query as CFDictionary),
		localizedError: NSLocalizedString("Deleting internet password from keychain failed.", tableName: "KeychainAccess", comment: "Attempt to delete a keychain item failed."))
}

// MARK: - Private

/// User-visible label for internet passwords.
///
/// > Note: Added in v1.1.0.
private let InternetPasswordLabelAttribute = "KeychainWrapper Internet Password"

/// Contains the keychain primary key properties encoded in an `URL`.
///
/// > Note: Added in v1.1.0.
private struct URLPrimaryKeyData {
	/// `kSecAttrServer` value.
	let server: String

	/// `kSecAttrPort` value.
	let port: Int

	/// `kSecAttrPath` value.
	let path: String

	/// `kSecAttrProtocol` value.
	let protocolAttribute: ProtocolKeychainAttribute

	/// Extracts various primary key parts of keychain internet passwords from an URL.
	static func fromURL(_ url: URL) -> URLPrimaryKeyData {
		let server: String
		if #available(iOS 16.0, macOS 13.0, *) {
			server = url.host(percentEncoded: false) ?? ""
		} else {
			server = url.host ?? ""
		}

		let protocolAttribute = url.scheme.map { ProtocolKeychainAttribute.fromScheme($0) ?? ProtocolKeychainAttribute.https } ?? ProtocolKeychainAttribute.https

		return URLPrimaryKeyData(server: server, port: url.port ?? -1, path: url.path, protocolAttribute: protocolAttribute)
	}
}

/// Produces the query parameters with all primary key attributes for internet passwords.
@available(OSX 10.15, iOS 13.0, *)
private func baseKeychainQuery(account: String, securityDomain: String, server: String, port: Int, path: String, protocolAttribute: ProtocolKeychainAttribute, authenticationType: AuthenticationTypeKeychainAttribute) -> [CFString: Any] {
	// For internet passwords, the primary keys include kSecAttrAccount, kSecAttrSecurityDomain, kSecAttrServer, kSecAttrProtocol, kSecAttrAuthenticationType, kSecAttrPort, and kSecAttrPath.
        var query: [CFString : Any] = [
		kSecClass:                  kSecClassInternetPassword,
		kSecAttrAccount:            account,
		kSecAttrSecurityDomain:     securityDomain,
		kSecAttrServer:             server,
		kSecAttrProtocol:           protocolAttribute.queryValue,
		kSecAttrAuthenticationType: authenticationType.queryValue,
		kSecAttrPort:               NSNumber(value: port),
		kSecAttrPath:               path]

#if COMPILE_TEST
#else
	query[kSecUseDataProtectionKeychain] = true
#endif

	return query
}
