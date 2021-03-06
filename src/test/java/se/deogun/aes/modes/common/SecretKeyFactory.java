package se.deogun.aes.modes.common;

import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.util.Base64;

public class SecretKeyFactory {
    public static byte[] base64EncodedKey() {
        return Base64.getEncoder().encode(key());
    }

    public static byte[] key() {
        try {
            final var instance = KeyGenerator.getInstance("AES");
            instance.init(256, SecureRandom.getInstanceStrong());
            return instance.generateKey().getEncoded();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
