package se.deogun.aes;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;

/**
 * Main interface for interacting with an instantiated AES service
 */
public interface AES {
    /**
     * Encrypts the provided data using the mode defined when creating the AES instance
     * @param data plain text
     * @return result of the encrypt operation
     */
    Result<Throwable, byte[], AESRejectReason> encrypt(byte[] data);

    /**
     * Decrypts the provided data using the mode defined when creating the AES instance
     * @param data encrypted data
     * @return result of the decrypt operation
     */
    Result<Throwable, byte[], AESRejectReason> decrypt(byte[] data);
}
