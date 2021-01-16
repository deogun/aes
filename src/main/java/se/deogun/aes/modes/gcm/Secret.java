package se.deogun.aes.modes.gcm;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.spec.SecretKeySpec;
import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.isBase64;
import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

@SuppressWarnings("ExternalizableWithoutPublicNoArgConstructor")
public final class Secret implements Externalizable, Serializable {
    private transient final SecretKeySpec keySpec;

    public Secret(final String encodedKey) {
        this(notNull(encodedKey).getBytes());
    }

    public Secret(final byte[] encodedKey) {
        notNull(encodedKey);

        this.keySpec = new SecretKeySpec(isBase64(encodedKey) ? decodeBase64(encodedKey) : encodedKey, "AES");
    }

    public final SecretKeySpec keySpecification() {
        return keySpec;
    }

    @Override
    public final void writeExternal(final ObjectOutput out)  {
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
