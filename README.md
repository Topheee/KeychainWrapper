# KeychainWrapper

Wrapper around the Keychain API on iOS and macOS.

The methods are wrappers around the different Keychain classes and require the properties that fully qualify a Keychain item.
> See the [documentation](https://developer.apple.com/documentation/security/errsecduplicateitem) for a list of the primary keys per class.

## Known Issues

The Keychain queries used by the deprecated `…Secret…Keychain()` functions are not 'fully qualified', meaning that if a secret is created with the same label and additional parameters (for instance `kSecAttrAccount`), this additional secret will interfere with the ones created by this library.

To prevent this issue, do not use the deprecated methods or make sure that the labels used for the secrets managed by this library are unique in the program.

## Testing

Invoke the tests with:
```swift
swift test -Xswiftc -DCOMPILE_TEST
```

This is necessary since I did not get the `kSecUseDataProtectionKeychain` option to work during testing on macOS, it always throws `errSecMissingEntitlement`.

They are still failing, since SecKeyGeneratePair behaves differently on iOS and macOS … and it probably won't anymore if I can get `kSecUseDataProtectionKeychain` to run on macOS.

## Further Info
- [Primary Keys](https://developer.apple.com/documentation/security/errsecduplicateitem)
- [kSecAttrApplicationLabel](https://developer.apple.com/documentation/security/ksecattrapplicationlabel)
- [Symmetric Items are not supported](https://stackoverflow.com/questions/22172229/how-to-use-secitemadd-to-store-a-symmetric-key-in-os-x)
- [SecKeyGeneratePair](https://developer.apple.com/documentation/security/1395339-seckeygeneratepair)
