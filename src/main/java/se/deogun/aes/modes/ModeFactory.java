package se.deogun.aes.modes;

import java.util.function.Function;

import static se.deogun.aes.modes.InternalValidation.*;

/**
 * Factory to create a encryption / decryption mode to
 * be used with AES
 */
public final class ModeFactory {
    public static <T>T gcm(final Function<AADMode, T> aes, final int decryptBufferSize) {
        isNotNull(aes);
        isTrue(isInRange(decryptBufferSize, 8 * 1024, 1024 * 1024));

        return aes.apply(new GCM(decryptBufferSize));
    }

    public static <T>T cbc(final Function<NonAADMode, T> aes, final int decryptBufferSize) {
        isNotNull(aes);
        isTrue(isInRange(decryptBufferSize, 8 * 1024, 1024 * 1024));

        return aes.apply(new CBC(decryptBufferSize));
    }
}
