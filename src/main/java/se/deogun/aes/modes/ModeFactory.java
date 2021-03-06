package se.deogun.aes.modes;

import java.util.function.Function;

import static se.deogun.aes.modes.InternalValidation.isNotNull;

/**
 * Factory to create a encryption / decryption mode to
 * be used with AES
 */
public final class ModeFactory {
    public static <T>T gcm(final Function<Mode, T> aes) {
        isNotNull(aes);
        return aes.apply(new GCM());
    }
}
