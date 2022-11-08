import XCTest
@testable import KeychainWrapper

final class KeychainWrapperTests: XCTestCase {
	func testOperationsFailOnNonExistantKeys() throws {
		XCTAssertThrowsError(try removeSecretFromKeychain(label: "non-existant"))
	}
}

final class DataExtensionTests: XCTestCase {
	func testOperationsFailOnNonExistantKeys() throws {
		let begin = "hell"
		let first = "hello"
		let second = "\(begin)o"

		guard let firstData = first.data(using: .utf8),
			  let secondData = second.data(using: .utf8) else {
			XCTAssert(false)
			return
		}

		XCTAssertEqual(firstData.sha256(), secondData.sha256())
	}
}

final class AsymmetricCryptoTests: XCTestCase {
	/// Keychain property
	public static let KeyType = kSecAttrKeyTypeEC
	/// Keychain property
	public static let KeySize = 256 // SecKeySizes.secp256r1.rawValue as AnyObject, only available on macOS...

	func testEncoding() throws {
		guard let privateTag = "privateTag".data(using: .utf8),
			  let publicTag = "publicTag".data(using: .utf8) else {
			XCTAssert(false)
			return
		}
		let keyPair = try KeyPair(label: "test", privateTag: privateTag, publicTag: publicTag, type: AsymmetricCryptoTests.KeyType, size: AsymmetricCryptoTests.KeySize, persistent: false)
		let encoder = JSONEncoder()
		let data = try encoder.encode(keyPair.publicKey)
		let decoder = JSONDecoder()
		let decodedPublicKey = try decoder.decode(AsymmetricPublicKey.self, from: data)
		XCTAssertEqual(try keyPair.publicKey.externalRepresentation(), try decodedPublicKey.externalRepresentation())
	}
}
