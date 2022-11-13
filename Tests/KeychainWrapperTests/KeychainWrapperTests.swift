import XCTest
@testable import KeychainWrapper

final class KeychainWrapperTests: XCTestCase {
	private let SecretKey = "MyTestSecret"

	override func setUpWithError() throws {
	// Put setup code here. This method is called before the invocation of each test method in the class.
		try? removeSecretFromKeychain(label: SecretKey)
	}

	func testDeleteFailsOnNonExistantKeys() throws {
		XCTAssertThrowsError(try removeSecretFromKeychain(label: "non-existant"))
	}

	func testMultipleInsertOverwrites() throws {
		try persistSecretInKeychain(secret: "a", label: SecretKey)
		try persistSecretInKeychain(secret: "b", label: SecretKey)
		XCTAssertEqual(try secretFromKeychain(label: SecretKey), "b")
	}

	func testOtherKeysAreNotInterferring() throws {
		let query: [String: Any] = [kSecClass as String:   kSecClassGenericPassword,
			 kSecAttrLabel as String:   SecretKey,
			 kSecAttrGeneric as String: (SecretKey.data(using: .utf8) ?? Data()) as CFData,
			 kSecValueData as String:   (SecretKey.data(using: .utf8) ?? Data()) as CFData]
		try SecKey.check(status: SecItemAdd(query as CFDictionary, nil), localizedError: NSLocalizedString("Adding secret to keychain failed.", tableName: "KeychainAccess", comment: "SecItemAdd failed"))

		let query2: [String: Any] = [kSecClass as String:   kSecClassGenericPassword,
			 kSecAttrLabel as String:   SecretKey,
			 kSecAttrService as String: SecretKey,
			 kSecValueData as String:   (SecretKey.data(using: .utf8) ?? Data()) as CFData]
		try SecKey.check(status: SecItemAdd(query2 as CFDictionary, nil), localizedError: NSLocalizedString("Adding secret to keychain failed.", tableName: "KeychainAccess", comment: "SecItemAdd failed"))

                try persistSecretInKeychain(secret: "a", label: SecretKey)
		XCTAssertEqual(try secretFromKeychain(label: SecretKey), "a")
                try persistSecretInKeychain(secret: "b", label: SecretKey)
		XCTAssertEqual(try secretFromKeychain(label: SecretKey), "b")
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
