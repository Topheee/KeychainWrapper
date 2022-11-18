import XCTest
@testable import KeychainWrapper

final class GenericPasswordTests: XCTestCase {
	private let normalAccount = "MyTestSecret"
	private let normalService = "example.com"

	override func setUpWithError() throws {
		// Put setup code here. This method is called before the invocation of each test method in the class.
		try? removeGenericPasswordFromKeychain(account: normalAccount, service: normalService)
	}

	func testNormalOperation() throws {
		let encoding = String.Encoding.utf8

		let pwData = "a".data(using: encoding) ?? Data()
		XCTAssertNoThrow(try persistGenericPasswordInKeychain(pwData, account: normalAccount, service: normalService))
		XCTAssertEqual(try genericPasswordFromKeychain(account: normalAccount, service: normalService), pwData)
		XCTAssertEqual(try genericPasswordFromKeychain(account: normalAccount, service: normalService, encoding: encoding), "a")
		XCTAssertNoThrow(try removeGenericPasswordFromKeychain(account: normalAccount, service: normalService))
		XCTAssertThrowsError(try genericPasswordFromKeychain(account: normalAccount, service: normalService))
		XCTAssertThrowsError(try genericPasswordFromKeychain(account: normalAccount, service: normalService, encoding: encoding))
	}

	func testUnusualPrimaryKeyValues() throws {
		let pwData = "a".data(using: .utf8) ?? Data()
		let strangeValue = "`&$§"
		XCTAssertNoThrow(try persistGenericPasswordInKeychain(pwData, account: strangeValue, service: strangeValue))
		XCTAssertEqual(try genericPasswordFromKeychain(account: strangeValue, service: strangeValue), pwData)
	}

	func testDeleteFailsOnNonExistantAccount() throws {
		XCTAssertThrowsError(try removeGenericPasswordFromKeychain(account: "non-existant", service: normalService))
		XCTAssertThrowsError(try removeGenericPasswordFromKeychain(account: normalAccount, service: "non-existant"))
		XCTAssertThrowsError(try removeGenericPasswordFromKeychain(account: "non-existant", service: "non-existant"))
	}
}
