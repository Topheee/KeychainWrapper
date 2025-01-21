# KeychainWrapper

Swift 6 (`Sendable`-conforming) wrapper around the Keychain API on iOS and
macOS. Depends on `Foundation` only.

These types of keychain items are supported:

- Asymmetric keys
  - `kSecAttrKeyTypeECSECPrimeRandom`: P-192, P-256, P-384, and P-521 curves.
  - `kSecAttrKeyTypeRSA`: RSA keys.
- Symmetric keys
  - Internet passwords
  - Generic passwords

## Testing

Invoke the tests with:
```swift
swift test -Xswiftc -DCOMPILE_TEST
```

This is necessary since I did not get the `kSecUseDataProtectionKeychain`
option to work during testing on macOS; it always throws
`errSecMissingEntitlement`.

They are still failing, since `SecKeyGeneratePair` behaves differently on iOS
and macOS … and it probably won't anymore if I can get
`kSecUseDataProtectionKeychain` to run on macOS.

> Hint: Testing will create a lot of items in your Keychain app on macOS
beginning with `KeychainWrapper …` in your default keychain.
You can safely delete them.

## Further Info
- [Primary Keys](https://developer.apple.com/documentation/security/errsecduplicateitem)
- [kSecAttrApplicationLabel](https://developer.apple.com/documentation/security/ksecattrapplicationlabel)
- [Symmetric Items are not supported](https://stackoverflow.com/questions/22172229/how-to-use-secitemadd-to-store-a-symmetric-key-in-os-x)
- [SecKeyGeneratePair](https://developer.apple.com/documentation/security/1395339-seckeygeneratepair)
