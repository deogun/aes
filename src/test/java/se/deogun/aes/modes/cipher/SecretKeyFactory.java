package se.deogun.aes.modes.cipher;

import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.util.Base64;

public class SecretKeyFactory {
    public static byte[] secretKey() {
        return Base64.getEncoder().encode(nonBase64EncodedKey());
    }

    public static byte[] nonBase64EncodedKey() {
        try {
            final var instance = KeyGenerator.getInstance("AES");
            instance.init(256, SecureRandom.getInstanceStrong());
            return instance.generateKey().getEncoded();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
