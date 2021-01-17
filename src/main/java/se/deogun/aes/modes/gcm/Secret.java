package se.deogun.aes.modes.gcm;

import se.deogun.aes.modes.InternalValidationFailure;

import javax.crypto.spec.SecretKeySpec;
import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

@SuppressWarnings("ExternalizableWithoutPublicNoArgConstructor")
public final class Secret implements Externalizable, Serializable {
    private static final int PADDING = 61;
    private static final Set<Byte> BASE64_ALPHABET = base64Alphabet();
    private transient final SecretKeySpec keySpec;

    private Secret(final byte[] key) {
        isNotNull(key);
        this.keySpec = new SecretKeySpec(key, "AES");
    }

    public static Secret secret(final byte[] key) {
        isNotNull(key);
        return new Secret(key);
    }

    public static Secret secret(final String key) {
        isNotNull(key);
        return new Secret(key.getBytes(UTF_8));
    }

    public static Secret secretFromBase64EncodedKey(final String key) {
        isNotNull(key);
        satisfiesInvariant(satisfiesBase64(key.getBytes(UTF_8)));
        return new Secret(Base64.getDecoder().decode(key.getBytes(UTF_8)));
    }

    public static Secret secretFromBase64EncodedKey(final byte[] key) {
        isNotNull(key);
        satisfiesInvariant(satisfiesBase64(key));
        return new Secret(Base64.getDecoder().decode(key));
    }

    public final SecretKeySpec keySpecification() {
        return keySpec;
    }

    private static Set<Byte> base64Alphabet() {
        //See RFC 4648 Table 1.
        //Note: the padding character is excluded to allow detection of illegal occurrence before possible padding
        final var character = "+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".getBytes(UTF_8);
        final var alphabet = new HashSet<Byte>();

        for (final byte b : character) {
            alphabet.add(b);
        }
        return alphabet;
    }

    private static boolean satisfiesBase64(final byte[] candidate) {
        if (candidate.length % 4 != 0) {
            return false;
        }

        for (int i = 0; i < candidate.length; i++) {
            if (i < candidate.length - 3) {
                if(!BASE64_ALPHABET.contains(candidate[i])) {
                    return false;
                }
            } else if (!BASE64_ALPHABET.contains(candidate[i])) {
                if (candidate[i] != PADDING) {
                    return false;
                }
            }
        }
        return true;
    }

    private static void isNotNull(final byte[] input) {
        if (input == null) {
            throw new InternalValidationFailure();
        }
    }

    private static void isNotNull(final Object input) {
        if (input == null) {
            throw new IllegalArgumentException("Null not allowed as input");
        }
    }

    private static void satisfiesInvariant(final boolean invariant) {
        if (!invariant) {
            throw new IllegalArgumentException("Input violates invariant");
        }
    }

    @Override
    public final void writeExternal(final ObjectOutput out) {
        deny();
    }

    @Override
    public final void readExternal(final ObjectInput in) {
        deny();
    }

    @Override
    public final String toString() {
        return "***** SENSITIVE VALUE *****";
    }

    @Override
    public final boolean equals(final Object o) {
        return false;
    }

    @Override
    public final int hashCode() {
        return 0;
    }

    private static void deny() {
        throw new UnsupportedOperationException();
    }
}
