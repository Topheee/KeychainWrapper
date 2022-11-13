# KeychainWrapper

Wrapper around the Keychain API on iOS and macOS.

## Known Issues

The Keychain queries used by the `…Secret…Keychain()` functions are not 'fully qualified', meaning that if a secret is created with the same label and additional parameters (for instance `kSecAttrAccount`), this additional secret will interfere with the ones created by this library.

To prevent this issue, make sure that the labels used for the secrets managed by this library are unique in the program.

In a future version, we will most likely set the `kSecAttrGeneric´ attribute to a library-specific fixed value. However, this will be a breaking change, so you will need to copy the old secrets to the new values. If possible, we will provide migration functions.
