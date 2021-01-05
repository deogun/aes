package se.deogun.aes.algorithms;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.spec.SecretKeySpec;
import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

@SuppressWarnings("ExternalizableWithoutPublicNoArgConstructor")
public final class Secret implements Externalizable, Serializable {
    private transient final SecretKeySpec keySpec;

    public Secret(final String encodedKey) {
        this(notNull(encodedKey).getBytes());
    }

    public Secret(final byte[] key) {
        notNull(key);
        isTrue(Base64.isBase64(key));

        this.keySpec = new SecretKeySpec(Base64.decodeBase64(key), "AES");
    }

    public final SecretKeySpec keySpecification() {
        return keySpec;
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
