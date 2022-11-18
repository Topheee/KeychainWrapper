import XCTest
@testable import KeychainWrapper

final class InternetPasswordTests: XCTestCase {
	private let normalAccount = "MyTestSecret"
	private let normalSecurityDomain = "MyTestSecret"
	private let normalServer = "example.com"
	private let normalPort = 443
	private let normalPath = "/"
	private let normalAuthenticationType = AuthenticationTypeKeychainAttribute.`default`
	private let normalProtocol = ProtocolKeychainAttribute.https

	override func setUpWithError() throws {
		// Put setup code here. This method is called before the invocation of each test method in the class.
		try? removeInternetPasswordFromKeychain(account: normalAccount, securityDomain: normalSecurityDomain, server: normalServer, port: normalPort, path: normalPath, protocolAttribute: normalProtocol, authenticationType: normalAuthenticationType)
	}

	func testNormalOperation() throws {
		let pwData = "a".data(using: .utf8) ?? Data()
		XCTAssertNoThrow(try persistInternetPasswordInKeychain(pwData, account: normalAccount, securityDomain: normalSecurityDomain, server: normalServer, port: normalPort, path: normalPath, protocolAttribute: normalProtocol, authenticationType: normalAuthenticationType))
		XCTAssertEqual(try internetPasswordFromKeychain(account: normalAccount, securityDomain: normalSecurityDomain, server: normalServer, port: normalPort, path: normalPath, protocolAttribute: normalProtocol, authenticationType: normalAuthenticationType), pwData)
	}

	func testUnusualPrimaryKeyValues() throws {
		let pwData = "a".data(using: .utf8) ?? Data()
		let strangeValue = "`&$§"

		// make sure the item does not exist anymore
		try? removeInternetPasswordFromKeychain(account: strangeValue, securityDomain: strangeValue, server: strangeValue, port: -1, path: strangeValue, protocolAttribute: normalProtocol, authenticationType: normalAuthenticationType)

		XCTAssertNoThrow(try persistInternetPasswordInKeychain(pwData, account: strangeValue, securityDomain: strangeValue, server: strangeValue, port: -1, path: strangeValue, protocolAttribute: normalProtocol, authenticationType: normalAuthenticationType))
		XCTAssertEqual(try internetPasswordFromKeychain(account: strangeValue, securityDomain: strangeValue, server: strangeValue, port: -1, path: strangeValue, protocolAttribute: normalProtocol, authenticationType: normalAuthenticationType), pwData)
	}

	func testDeleteFailsOnNonExistantAccount() throws {
		XCTAssertThrowsError(try removeInternetPasswordFromKeychain(account: "non-existant", securityDomain: normalSecurityDomain, server: normalServer, port: normalPort, path: normalPath, protocolAttribute: normalProtocol, authenticationType: normalAuthenticationType))
	}
}
