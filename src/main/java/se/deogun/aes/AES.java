package se.deogun.aes;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;
import se.deogun.aes.modes.AAD;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Main interface for interacting with an instantiated AES service
 */
public interface AES {

    /**
     * Encrypts the provided data using the mode defined when creating the AES instance
     * @param data plain text
     * @param aad additional authentication data
     * @return result of the encrypt operation
     */
    Result<? super AESFailure, byte[], AESRejectReason> encrypt(byte[] data, AAD aad);

    /**
     * Encrypts the provided data using the mode defined when creating the AES instance
     * @param data plain text
     * @param outputStream output stream to which the encrypted data is written to
     * @param aad additional authentication data
     * @return result of the encrypt operation
     */
    Result<? super AESFailure, OutputStream, AESRejectReason> encrypt(byte[] data, OutputStream outputStream, AAD aad);

    /**
     * Decrypts the provided data using the mode defined when creating the AES instance
     * @param data encrypted data
     * @param aad additional authentication data
     * @return result of the encrypt operation
     */
    Result<? super AESFailure, byte[], AESRejectReason> decrypt(byte[] data, AAD aad);

    /**
     * Decrypts the provided data using the mode defined when creating the AES instance
     * @param inputStream encrypted data
     * @param aad additional authentication data
     * @return result of the decrypt operation
     */
    Result<? super AESFailure, byte[], AESRejectReason> decrypt(InputStream inputStream, AAD aad);
}
