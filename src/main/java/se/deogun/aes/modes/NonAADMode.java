package se.deogun.aes.modes;

import se.deogun.aes.modes.common.InternalRejectReason;
import se.deogun.aes.modes.common.Result;
import se.deogun.aes.modes.common.Secret;

import java.io.InputStream;
import java.io.OutputStream;
/**
 * AES mode for encrypting / decrypting data
 */
public interface NonAADMode {
    Result<Throwable, byte[], InternalRejectReason> encrypt(byte[] plainText, Secret secret);

    Result<Throwable, byte[], InternalRejectReason> decrypt(byte[] encryptedData, Secret secret);

    Result<Throwable, OutputStream, InternalRejectReason> encrypt(byte[] plainText, OutputStream outputStream, Secret secret);

    Result<Throwable, byte[], InternalRejectReason> decrypt(InputStream encryptedData, Secret secret);
}
