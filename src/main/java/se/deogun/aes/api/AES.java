package se.deogun.aes.api;

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
    Result<? super Failure, byte[], RejectReason> encrypt(byte[] data, AAD aad);

    /**
     * Encrypts the provided data using the mode defined when creating the AES instance
     * @param data plain text
     * @return result of the encrypt operation
     */
    Result<? super Failure, byte[], RejectReason> encrypt(byte[] data);

    /**
     * Encrypts the provided data using the mode defined when creating the AES instance
     * @param data plain text
     * @param outputStream output stream to which the encrypted data is written to
     * @param aad additional authentication data
     * @return result of the encrypt operation
     */
    Result<? super Failure, OutputStream, RejectReason> encrypt(byte[] data, OutputStream outputStream, AAD aad);

    /**
     * Encrypts the provided data using the mode defined when creating the AES instance
     * @param data plain text
     * @param outputStream output stream to which the encrypted data is written to
     * @return result of the encrypt operation
     */
    Result<? super Failure, OutputStream, RejectReason> encrypt(byte[] data, OutputStream outputStream);

    /**
     * Decrypts the provided data using the mode defined when creating the AES instance
     * @param data encrypted data
     * @param aad additional authentication data
     * @return result of the encrypt operation
     */
    Result<? super Failure, byte[], RejectReason> decrypt(byte[] data, AAD aad);

    /**
     * Decrypts the provided data using the mode defined when creating the AES instance
     * @param data encrypted data
     * @return result of the encrypt operation
     */
    Result<? super Failure, byte[], RejectReason> decrypt(byte[] data);

    /**
     * Decrypts the provided data using the mode defined when creating the AES instance
     * @param inputStream encrypted data
     * @param aad additional authentication data
     * @return result of the decrypt operation
     */
    Result<? super Failure, byte[], RejectReason> decrypt(InputStream inputStream, AAD aad);

    /**
     * Decrypts the provided data using the mode defined when creating the AES instance
     * @param inputStream encrypted data
     * @return result of the decrypt operation
     */
    Result<? super Failure, byte[], RejectReason> decrypt(InputStream inputStream);
}
