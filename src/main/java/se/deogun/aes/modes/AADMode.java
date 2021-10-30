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
public interface AADMode {
    Result<Throwable, OutputStream, InternalRejectReason> encrypt(byte[] plainText, OutputStream outputStream, Secret secret, AAD aad);

    Result<Throwable, byte[], InternalRejectReason> encrypt(byte[] plainText, Secret secret, AAD aad);

    Result<Throwable, byte[], InternalRejectReason> decrypt(InputStream encryptedData, Secret secret, AAD aad);

    Result<Throwable, byte[], InternalRejectReason> decrypt(byte[] encryptedData, Secret secret, AAD aad);
}
