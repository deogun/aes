package se.deogun.aes.algorithms;

/**
 * Context defining the AES algorithm to be used
 * @param <T> Context Type
 */
public interface AESContext<T> {
    /**
     * Supplies the encryption context
     * @return encryption context
     */
    T encryption();

    /**
     * Supplies the decryption context
     * @return decryption context
     */
    T decryption();
}
