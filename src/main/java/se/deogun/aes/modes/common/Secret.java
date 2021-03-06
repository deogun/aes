package se.deogun.aes.modes.common;

import javax.crypto.spec.SecretKeySpec;
import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.Arrays;

@SuppressWarnings("ExternalizableWithoutPublicNoArgConstructor")
public final class Secret implements Externalizable, Serializable {
    private transient final byte[] key;

    public Secret(final byte[] key) {
        notNull(key);
        this.key = clone(key);
    }

    public final SecretKeySpec keySpecification() {
        return new SecretKeySpec(clone(key), "AES");
    }

    private static byte[] clone(final byte[] data) {
        final var clone = data.clone();
        ensureEquals(clone, data);
        return clone;
    }

    private static void ensureEquals(final byte[] value1, final byte[] value2) {
        if(!Arrays.equals(value1, value2)) {
            throw new InternalValidationFailure();
        }
    }

    private static void notNull(final Object input) {
        if (input == null) {
            throw new InternalValidationFailure();
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
