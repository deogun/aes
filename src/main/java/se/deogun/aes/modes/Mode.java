package se.deogun.aes.modes;

import se.deogun.aes.modes.common.AAD;
import se.deogun.aes.modes.common.InternalRejectReason;
import se.deogun.aes.modes.common.Result;
import se.deogun.aes.modes.common.Secret;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * AES mode for encrypting / decrypting data
 */
public interface Mode {
    Result<Throwable, OutputStream, InternalRejectReason> encrypt(final byte[] plainText,
                                                                  final OutputStream outputStream,
                                                                  final Secret secret,
                                                                  final AAD aad);

    Result<Throwable, byte[], InternalRejectReason> encrypt(final byte[] plainText,
                                                            final Secret secret,
                                                            final AAD aad);

    Result<Throwable, byte[], InternalRejectReason> decrypt(final InputStream encryptedData,
                                                            final Secret secret,
                                                            final AAD aad);

    Result<Throwable, byte[], InternalRejectReason> decrypt(final byte[] encryptedData,
                                                            final Secret secret,
                                                            final AAD aad);
}
