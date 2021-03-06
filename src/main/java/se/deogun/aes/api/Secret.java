package se.deogun.aes.api;

import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.copyOf;

@SuppressWarnings("ExternalizableWithoutPublicNoArgConstructor")
public final class Secret implements Externalizable, Serializable {
    private static final int PADDING = 61;
    private static final Set<Byte> BASE64_ALPHABET = base64Alphabet();
    private transient final byte[] key;

    private Secret(final byte[] key) {
        notNull(key);
        this.key = copyOf(key, key.length);
    }

    public static Secret secretFromNonBase64EncodedKey(final byte[] key) {
        notNull(key);
        return new Secret(key);
    }

    public static Secret secretFromNonBase64EncodedKey(final String key) {
        notNull(key);
        return new Secret(key.getBytes(UTF_8));
    }

    public static Secret secretFromBase64EncodedKey(final String key) {
        notNull(key);
        satisfiesBase64Invariant(satisfiesBase64(key.getBytes(UTF_8)));
        return new Secret(Base64.getDecoder().decode(key.getBytes(UTF_8)));
    }

    public static Secret secretFromBase64EncodedKey(final byte[] key) {
        notNull(key);
        satisfiesBase64Invariant(satisfiesBase64(key));
        return new Secret(Base64.getDecoder().decode(key));
    }

    public final byte[] key() {
        return key.clone();
    }

    // See RFC 4648 Table 1.
    // Note: The padding character is excluded to allow detection of illegal occurrence before possible padding.
    private static Set<Byte> base64Alphabet() {
        final var character = "+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".getBytes(UTF_8);
        final var alphabet = new HashSet<Byte>();

        for (final byte b : character) {
            alphabet.add(b);
        }
        return alphabet;
    }

    // Please note that this isn't completely fool proof since it's impossible to know if a string is
    // Base64 encoded or not. For example, the string "aaaa" satisfies the Base64 requirements regardless if
    // it is encoded or not.
    private static boolean satisfiesBase64(final byte[] candidate) {
        // The length of a valid Base64 encoded string must be divisible by 4
        if (candidate.length % 4 != 0) {
            return false;
        }

        for (int i = 0; i < candidate.length; i++) {
            // Padding is only allowed in the last three bytes. Hence no padding character
            // is allowed prior to those.
            if (i < candidate.length - 3) {
                if (!BASE64_ALPHABET.contains(candidate[i])) {
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

    private static void notNull(final Object input) {
        if (input == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
    }

    private static void satisfiesBase64Invariant(final boolean invariant) {
        if (!invariant) {
            throw new IllegalArgumentException("Input violates Base64 invariant");
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
