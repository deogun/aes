package se.deogun.aes.algorithms;

import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.UUID;
import java.util.function.Function;

import static java.util.Arrays.copyOf;
import static java.util.Arrays.copyOfRange;
import static org.apache.commons.lang3.Validate.*;
import static se.deogun.aes.algorithms.InitVector.DataSelectionStrategy.FIRST_12_BYTES;

@SuppressWarnings("ExternalizableWithoutPublicNoArgConstructor")
public final class InitVector implements Externalizable, Serializable {
    public enum DataSelectionStrategy {
        FIRST_12_BYTES((byte[] data) -> copyOfRange(data, 0, 12)),
        MID_12_BYTES((byte[] data) -> copyOfRange(data, data.length / 2 - 6, data.length / 2 + 6)),
        LAST_12_BYTES((byte[] data) -> copyOfRange(data, data.length - 12, data.length));

        final Function<byte[], byte[]> function;

        DataSelectionStrategy(final Function<byte[], byte[]> function) {
            this.function = function;
        }
    }

    private transient final byte[] value;

    public InitVector(final UUID data) {
        this(notEmpty(notNull(data).toString().replace("-","")).getBytes(), FIRST_12_BYTES);
    }

    public InitVector(final String data) {
        this(notEmpty(data).getBytes(), FIRST_12_BYTES);
    }

    public InitVector(final String data, final DataSelectionStrategy strategy) {
        this(notEmpty(data).getBytes(), notNull(strategy));
    }

    private InitVector(final byte[] data, final DataSelectionStrategy strategy) {
        notNull(strategy);
        notNull(data);
        isTrue(data.length > 11); // We need to ensure we have at least 12 bytes
        isTrue(data.length < 4096); //Just to have an upper bound

        this.value = notNull(strategy.function.apply(data));
    }

    public byte[] value() {
        return copyOf(value, value.length);
    }

    @Override
    public void writeExternal(final ObjectOutput out)  {
        deny();
    }

    @Override
    public void readExternal(final ObjectInput in) {
        deny();
    }

    @Override
    public String toString() {
        return "***** SENSITIVE VALUE *****";
    }

    @Override
    public boolean equals(final Object o) {
        return false;
    }

    @Override
    public int hashCode() {
        return 0;
    }

    private static void deny() {
        throw new UnsupportedOperationException();
    }
}
