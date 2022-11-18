import XCTest
@testable import KeychainWrapper

final class KeyItemTests: XCTestCase {
	/// Regular application tag.
	private let normalTag = "MyTag".data(using: .utf8) ?? Data()

	/// Regular application tag.
	private let normalPublicTag = "MyPublicTag".data(using: .utf8) ?? Data()

	/// Regular application tag.
	private let normalPrivateTag = "MyPrivateTag".data(using: .utf8) ?? Data()

	/// Common key size for EC keys.
	private let normalECAsymmetricKeySize = 256

	/// The plain text message we want to operate on.
	private let plainTextMessage = "The quick brown fox jumps over the lazy dog".data(using: .utf8) ?? Data()

	/// Is the happy path working for asymmetric keys?
	func testNormalAsymmetricKeyOperation() throws {
		let ecAlgorithm = AsymmetricAlgorithm.ec

		XCTAssertNoThrow(try generateAsymmetricKeyPair(privateTag: normalPrivateTag, publicTag: normalPublicTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize, persistent: false, useEnclave: false))
		XCTAssertNoThrow(try generateAsymmetricKeyPair(privateTag: normalPrivateTag, publicTag: normalPublicTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize, persistent: true, useEnclave: false))

		XCTAssertNoThrow(try publicKeyDataFromKeychain(tag: normalPublicTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize))

		// should throw error since the key is set to be non-extractible
		XCTAssertThrowsError(try privateKeyDataFromKeychain(tag: normalPrivateTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize))

		XCTAssertNoThrow(try publicKeyDataFromKeychain(tag: normalPrivateTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize))

		XCTAssertNoThrow(try removePublicKeyFromKeychain(tag: normalPrivateTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize))
		XCTAssertNoThrow(try removePrivateKeyFromKeychain(tag: normalPrivateTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize))
	}
}
