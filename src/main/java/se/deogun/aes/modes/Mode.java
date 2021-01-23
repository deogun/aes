package se.deogun.aes.modes;

import se.deogun.aes.modes.cipher.AAD;
import se.deogun.aes.modes.cipher.Secret;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * AES mode for encrypting / decrypting data
 */
public interface Mode {
    Result<Throwable, OutputStream, AESRejectReason> encrypt(final byte[] plainText,
                                                             final OutputStream outputStream,
                                                             final Secret secret,
                                                             final AAD aad);

    Result<Throwable, byte[], AESRejectReason> encrypt(final byte[] plainText,
                                                       final Secret secret,
                                                       final AAD aad);

    Result<Throwable, byte[], AESRejectReason> decrypt(final InputStream encryptedData,
                                                       final Secret secret,
                                                       final AAD aad);

    Result<Throwable, byte[], AESRejectReason> decrypt(final byte[] encryptedData,
                                                       final Secret secret,
                                                       final AAD aad);
}
