//
//  SupportingFunctions.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 06.10.2022.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

/// A hard-coded value provided for the `kSecAttrDescription` attribute when inserting passwords.
///
/// > Note: Added in v1.1.0.
let KeychainWrapperDescriptionAttribute = "KeychainWrapper managed item"

/// A hard-coded value provided for the `kSecAttrComment` attribute when inserting passwords.
///
/// > Note: Added in v1.1.0.
let KeychainWrapperCommentAttribute = "This item was generated by KeychainWrapper."

/// Retrieves the error message describing `status`.
func errorMessage(describing status: OSStatus) -> String {
	let fallbackMessage = "OSStatus \(status)"
	let msg: String
	#if os(OSX)
		msg = "\(SecCopyErrorMessageString(status, nil) ?? fallbackMessage as CFString)"
	#else
		if #available(iOS 11.3, *) {
			msg = "\(SecCopyErrorMessageString(status, nil) ?? fallbackMessage as CFString)"
		} else {
			perror(nil)
			msg = fallbackMessage
		}
	#endif
	return msg
}

/// Throwing wrapper around `SecRandomCopyBytes(_:_:_:)`.
func generateRandomData(length: Int) throws -> Data {
	var nonce = Data(count: length)
	let status = nonce.withUnsafeMutablePointer({ SecRandomCopyBytes(kSecRandomDefault, length, $0) })
	if status == errSecSuccess {
		return nonce
	} else {
		throw makeError(from: status)
	}
}

/// Converts an `OSStatus` returned by a security function to an `Error`.
func makeError(from status: OSStatus) -> Error {
	return NSError(domain: kCFErrorDomainOSStatus as String, code: Int(status),
		userInfo: [NSLocalizedDescriptionKey : errorMessage(describing: status)])
}

/// The `domain` value of errors created within this package.
///
/// > Note: Errors from other domains, such as `NSCocoaErrorDomain`, may still be thrown.
let ErrorDomain = "KeychainAccessErrorDomain";

/// Creates an Error indicating a malformed keychain entry.
func makeEmptyKeychainDataError() -> Error {
	return NSError(domain: ErrorDomain, code: NSFormattingError,
		userInfo: [NSLocalizedDescriptionKey : NSLocalizedString("Keychain data is empty or not UTF-8 encoded.",
			tableName: "KeychainAccess", bundle: .module, comment: "Error description for cryptographic operation failure")])
}

/// Creates an Error indicating a `String` cannot be encoded to `Data`.
///
/// > Note: Added in v1.1.0.
func makeStringEncodingError() -> Error {
	return NSError(domain: ErrorDomain, code: NSFormattingError,
		userInfo: [NSLocalizedDescriptionKey : NSLocalizedString("String encoding failed.",
			tableName: "KeychainAccess", bundle: .module, comment: "Error description for serialization operation failure.")])
}

/// Creates an Error indicating a `String` cannot be encoded to `Data`.
///
/// > Note: Added in v1.1.0.
func makeStringDecodingError() -> Error {
	return NSError(domain: ErrorDomain, code: NSFormattingError,
		userInfo: [NSLocalizedDescriptionKey : NSLocalizedString("String decoding failed.",
			tableName: "KeychainAccess", bundle: .module, comment: "Error description for serialization operation failure.")])
}

/// Creates an Error which is likely a development error within this library.
///
/// > Note: Added in v1.1.0.
func makeFatalError() -> Error {
	return NSError(domain: ErrorDomain, code: -1, userInfo: nil)
}

extension Data {
	/// Thrown when `count` is zero.
	public struct EmptyError: Error {}

	/// Allows operations on the binary data via an `UnsafePointer`.
	///
	/// This function is a replacement of the old `mutating func withUnsafeBytes<ResultType, ContentType>(_ body: (UnsafePointer<ContentType>) throws -> ResultType) rethrows -> ResultType`.
	/// - Throws: An `EmptyError` error is thrown if `count` is zero, or the error thrown by `body`.
	func withUnsafePointer<ResultType, ContentType>(_ body: (UnsafePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		return try self.withUnsafeBytes { (bufferPointer: UnsafeRawBufferPointer) in
			guard let bytePointer = bufferPointer.bindMemory(to: ContentType.self).baseAddress else { throw EmptyError() }
			return try body(bytePointer)
		}
	}

	/// Allows operations on the binary data via an `UnsafeMutablePointer`.
	///
	/// This function is a replacement of the old `mutating func withUnsafeMutableBytes<ResultType, ContentType>(_ body: (UnsafeMutablePointer<ContentType>) throws -> ResultType) rethrows -> ResultType`.
	/// - Throws: An `EmptyError` error is thrown if `count` is zero, or the error thrown by `body`.
	mutating func withUnsafeMutablePointer<ResultType, ContentType>(_ body: (UnsafeMutablePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		return try self.withUnsafeMutableBytes { (bufferPointer: UnsafeMutableRawBufferPointer) in
			guard let bytePointer = bufferPointer.bindMemory(to: ContentType.self).baseAddress else { throw EmptyError() }
			return try body(bytePointer)
		}
	}
}
