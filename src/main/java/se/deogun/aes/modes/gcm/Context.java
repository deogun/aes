package se.deogun.aes.modes.gcm;

import se.deogun.aes.modes.Secret;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.commons.lang3.Validate.notNull;

public final class Context implements Externalizable, Serializable {
    private final transient Secret secret;
    private final transient AAD aad;

    public Context(final Secret secret, final AAD aad) {
        this.secret = notNull(secret);
        this.aad = notNull(aad);
    }

    public final SecretKeySpec secret() {
        return secret.keySpecification();
    }

    public final byte[] aad() {
        return aad.value();
    }

    @Override
    public void writeExternal(final ObjectOutput out) {
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
