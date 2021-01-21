# Advanced Encryption Standard (AES) Service
This library allows you to create an AES service with following modes
- Galois/Counter Mode (GCM)

### Example usage – AES with GCM
Instantiate an AES service with a secret
```
final var aes = AESFactory.aesGCM(new Secret(<secret as bytes>));
```

Encrypt your plain text by
```
final var aad = new AAD("some aad data");
final var result = aes.encrypt(plainText, aad);
```

The `result` object requires you to take the following actions
```
result.handle(success -> success
              .accept(value -> <actions on encrypted value> )
              .reject(value -> <actions if encryption was rejected> ))
      .or(failure -> <actions if the encryption failed> );
```

If needed, you may also extract the encrypted value by using
```
final var encrypted = result.liftAccept();
```

To decrypt, you need to use the same secret and AAD
```
aes.decrypt(encrypted, aad)
       .handle(success -> success
              .accept(value -> <actions on decrypted value> )
              .reject(value -> <actions if decryption was rejected> ))
      .or(failure -> <actions if the decryption failed> );
```

### Known Limitations
- The buffer load size in GCM is fixed to 16 KB when decrypting input streams. This is efficient on most 
  systems, but it might need to be variable. Buffer size will become configurable in future releases.