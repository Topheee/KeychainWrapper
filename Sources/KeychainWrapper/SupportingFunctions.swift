//
//  SupportingFunctions.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 06.10.2022.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation
import CommonCrypto

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
	return NSError(domain: kCFErrorDomainOSStatus as String, code: Int(status), userInfo: [NSLocalizedDescriptionKey : errorMessage(describing: status)])
}

extension Data {
	/// Thrown when `count` is zero.
	public struct EmptyError: Error {}

	/// Computes the SHA-256 digest hash of this data.
	public func sha256() -> Data {
		let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
		var digest = Data(count: digestLength)
		_ = digest.withUnsafeMutablePointer({ (digestMutableBytes) in
			self.withUnsafePointer({ (plainTextBytes) in
				CC_SHA256(plainTextBytes, CC_LONG(self.count), digestMutableBytes)
			})
		})
		return digest
	}

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
