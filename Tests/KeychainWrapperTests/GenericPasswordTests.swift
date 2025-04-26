//
//  AsymmetricCryptoTests.swift
//  KeychainWrapper
//
//  Created by Christopher Kobusch on 13.04.25.
//  Copyright © 2025 Christopher Kobusch. All rights reserved.
//

// Platform Dependencies
import Foundation

// Test Dependencies
import Testing

@testable import KeychainWrapper

fileprivate struct ItemIdentifier {
	let account: String
	let service: String
}

@Suite(.serialized) actor GenericPasswordTests {
	private func generateItemID() -> ItemIdentifier {
		let id = UUID()
		return ItemIdentifier(
			account: "KeychainWrapper.Account.\(id)",
			service: "KeychainWrapper.Service.\(id)")
	}

	/// Working with generic passwords.
	@Test func testCreateDelete() throws {
		let id = generateItemID()

		let encoding = String.Encoding.utf8
		let pwData = "a".data(using: encoding) ?? Data()

		try persistGenericPasswordInKeychain(
			pwData, account: id.account, service: id.service)

		try removeGenericPasswordFromKeychain(
			account: id.account, service: id.service)
	}

	/// Working with generic passwords.
	@Test func testReadGenericPassword() throws {
		let id = generateItemID()

		let encoding = String.Encoding.utf8
		let pwData = "a".data(using: encoding) ?? Data()

		try persistGenericPasswordInKeychain(
			pwData, account: id.account, service: id.service)
		defer {
			try? removeGenericPasswordFromKeychain(
				account: id.account, service: id.service)
		}

		#expect(try genericPasswordFromKeychain(
			account: id.account, service: id.service) == pwData)
	}

	/// Working with generic passwords.
	@Test func testReadEncodedGenericPassword() throws {
		let id = generateItemID()

		let encoding = String.Encoding.utf8
		let pwData = "a".data(using: encoding) ?? Data()

		try persistGenericPasswordInKeychain(
			pwData, account: id.account, service: id.service)
		defer {
			try? removeGenericPasswordFromKeychain(
				account: id.account, service: id.service)
		}

		#expect(try genericPasswordFromKeychain(
			account: id.account, service: id.service,
			encoding: encoding) == "a")
	}

	/// Working with generic passwords.
	@Test func testUseAfterDeleteGenericPassword() throws {
		let id = generateItemID()

		let encoding = String.Encoding.utf8
		let pwData = "a".data(using: encoding) ?? Data()

		try persistGenericPasswordInKeychain(
			pwData, account: id.account, service: id.service)
		defer {
			try? removeGenericPasswordFromKeychain(
				account: id.account, service: id.service)
		}

		try removeGenericPasswordFromKeychain(
			account: id.account, service: id.service)

		#expect(throws: Error.self) {
			try genericPasswordFromKeychain(
				account: id.account, service: id.service)
		}

		#expect(throws: Error.self) {
			try genericPasswordFromKeychain(
				account: id.account, service: id.service,
				encoding: encoding)
		}
	}

	/// Working with generic passwords.
	@Test func testDoubleCreate() throws {
		let id = generateItemID()

		let encoding = String.Encoding.utf8
		let pwData = "a".data(using: encoding) ?? Data()

		try persistGenericPasswordInKeychain(
			pwData, account: id.account, service: id.service)
		defer {
			try? removeGenericPasswordFromKeychain(
				account: id.account, service: id.service)
		}

		#expect(throws: Error.self,
				"creating the same password twice should fail") {
			try persistGenericPasswordInKeychain(
				pwData, account: id.account,
				service: id.service)
		}

		try removeGenericPasswordFromKeychain(
			account: id.account, service: id.service)
	}

	/// Working with special characters.
	@Test func testUnusualPrimaryKeyValues() throws {
		let pwData = "a".data(using: .utf8) ?? Data()
		let strangeValue = "`&$§"

		try persistGenericPasswordInKeychain(
			pwData, account: strangeValue, service: strangeValue)
		defer {
			try? removeGenericPasswordFromKeychain(
				account: strangeValue, service: strangeValue)
		}

		#expect(try genericPasswordFromKeychain(
			account: strangeValue, service: strangeValue) == pwData)
	}

	@Test func testDeleteFailsOnNonExistingAccount() throws {
		let id = generateItemID()

		#expect(throws: Error.self) {
			try removeGenericPasswordFromKeychain(
				account: "non-existent", service: id.service)
		}

		#expect(throws: Error.self) {
			try removeGenericPasswordFromKeychain(
				account: id.account, service: "non-existent")
		}

		#expect(throws: Error.self) {
			try removeGenericPasswordFromKeychain(
				account: "non-existent", service: "non-existent")
		}
	}
}
