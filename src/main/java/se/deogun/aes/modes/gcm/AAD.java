package se.deogun.aes.modes.gcm;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.copyOf;

public final class AAD {
    private final transient byte[] value;

    public AAD(final String value) {
        isValid(value);
        satisfiesUpperBound(value.getBytes().length < 8193); //Just to have an upper bound

        this.value = value.getBytes(UTF_8);
    }

    public final byte[] value() {
        return copyOf(value, value.length);
    }

    private static void isValid(final String input) {
        if(input == null || input.isBlank()) {
            throw new IllegalArgumentException("Null or blank not allowed as input");
        }
    }

    private static void satisfiesUpperBound(final boolean predicate) {
        if(!predicate) {
            throw new IllegalArgumentException("Invariant failure for input");
        }
    }
}
