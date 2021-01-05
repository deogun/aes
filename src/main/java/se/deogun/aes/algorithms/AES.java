package se.deogun.aes.algorithms;

public interface AES {
    Result<Throwable, byte[], AESRejectReason> encrypt(byte[] data);

    Result<Throwable, byte[], AESRejectReason> decrypt(byte[] data);
}
