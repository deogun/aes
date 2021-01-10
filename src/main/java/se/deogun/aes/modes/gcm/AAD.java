package se.deogun.aes.modes.gcm;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.copyOf;
import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notEmpty;

public final class AAD {
    private final transient byte[] value;

    public AAD(final String value) {
        notEmpty(value);
        isTrue(value.getBytes().length < 8193); //Just to have an upper bound

        this.value = value.getBytes(UTF_8);
    }

    public final byte[] value() {
        return copyOf(value, value.length);
    }
}
