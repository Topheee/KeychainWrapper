import XCTest
@testable import KeychainWrapper

final class AsymmetricCryptoTests: XCTestCase {
	/// A regular tag used for identification of the public key.
	private let normalPublicTag = "MyPublicTag".data(using: .utf8) ?? Data()

	/// A regular tag used for identification of the private key.
	private let normalPrivateTag = "MyPrivateTag".data(using: .utf8) ?? Data()

	/// Common size for elliptic curve keys.
	private let normalECAsymmetricKeySize = 256

	/// The message we want to operate on.
	private let plainTextMessage = "The quick brown fox jumps over the lazy dog".data(using: .utf8) ?? Data()

	/// Is the happy path working?
	func testNormalAsymmetricKeyOperation() throws {
		let ecAlgorithm = AsymmetricAlgorithm.ec
		let keyPair = try KeyPair(privateTag: normalPrivateTag, publicTag: normalPublicTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize, persistent: false, useEnclave: false)

		// Since the key pair was not persisted we should not be able to obtain it from the keychain.
		XCTAssertThrowsError(try KeyPair(fromKeychainWithPrivateTag: normalPrivateTag, publicTag: normalPublicTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize))

		let signature = try keyPair.sign(message: plainTextMessage)
		XCTAssertNoThrow(try keyPair.verify(message: plainTextMessage, signature: signature))
	}


	/// Does converting the public key to binary and back work?
	func testSerialization() throws {
		let ecAlgorithm = AsymmetricAlgorithm.ec

		let keyPair = try KeyPair(privateTag: normalPrivateTag, publicTag: normalPublicTag, algorithm: ecAlgorithm, size: normalECAsymmetricKeySize, persistent: false)
		let encoder = JSONEncoder()
		let data = try encoder.encode(keyPair.publicKey)
		let decoder = JSONDecoder()
		let decodedPublicKey = try decoder.decode(AsymmetricPublicKey.self, from: data)
		XCTAssertEqual(try keyPair.publicKey.externalRepresentation(), try decodedPublicKey.externalRepresentation())
	}
}
