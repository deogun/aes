package se.deogun.aes.algorithms;

public interface AESContext<T> {
    T encryption();

    T decryption();
}
