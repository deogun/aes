package se.deogun.aes.api;

public enum DecryptBufferSize {
    _8KB_DECRYPT_BUFFER_SIZE(8),
    _16KB_DECRYPT_BUFFER_SIZE(16),
    _32KB_DECRYPT_BUFFER_SIZE(32),
    _64KB_DECRYPT_BUFFER_SIZE(64),
    _128KB_DECRYPT_BUFFER_SIZE(128),
    _256KB_DECRYPT_BUFFER_SIZE(256),
    _512KB_DECRYPT_BUFFER_SIZE(512),
    _1024KB_DECRYPT_BUFFER_SIZE(1024);

    public final int size;

    DecryptBufferSize(final int size) {
        this.size = size * 1024; //KB
    }
}
