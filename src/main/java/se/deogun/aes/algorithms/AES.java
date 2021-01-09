package se.deogun.aes.algorithms;

/**
 * Main interface for interacting with an instantiated AES service
 */
public interface AES {
    /**
     * Encrypts the provided data using the algorithm defined by the AES context
     * @param data data to be encrypted
     * @return result of the encrypt operation
     */
    Result<Throwable, byte[], AESRejectReason> encrypt(byte[] data);

    /**
     * Decrypts the provided data using the algorithm defined by the AES context
     * @param data data to be decrypted
     * @return result of the decrypt operation
     */
    Result<Throwable, byte[], AESRejectReason> decrypt(byte[] data);
}
