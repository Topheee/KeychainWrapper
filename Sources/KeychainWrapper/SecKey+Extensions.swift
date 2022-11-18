//
//  SecKey+Extensions.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 06.10.2022.
//  Copyright © 2022 Christopher Kobusch. All rights reserved.
//

import Foundation

extension SecKey {
	/// Throws an error when `status` indicates a failure, otherwise does nothing.
	///
	/// - Parameter status: The status code returned by a security operation.
	/// - Parameter localizedError: The error message added as `NSLocalizedDescriptionKey` to the thrown error.
	///
	/// - Throws: An `NSError` when `status` is not `errSecSuccess`, with `NSLocalizedFailureReasonErrorKey` set to the error message corresponding to `status`.
	static func check(status: OSStatus, localizedError: String) throws {
		guard status != errSecSuccess else { return }

		let msg = errorMessage(describing: status)
		let userInfo: [String : Any] = [
			NSLocalizedDescriptionKey:        localizedError,
			NSLocalizedFailureReasonErrorKey: msg,
			NSLocalizedFailureErrorKey:       makeError(from: status)]
		throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: userInfo)
	}
}
