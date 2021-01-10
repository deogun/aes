package se.deogun.aes.modes.gcm;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.Secret;

import java.io.ObjectInput;
import java.io.ObjectOutput;

import static java.util.UUID.randomUUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static se.deogun.aes.AESContextFactory.gcm;
import static se.deogun.aes.modes.SecretKeyFactory.secretKey;

class GCMContextTest {
    @Test
    void should_not_allow_externalization() {
        final var context = context();

        assertThrows(UnsupportedOperationException.class, () -> context.writeExternal(mock(ObjectOutput.class)));
        assertThrows(UnsupportedOperationException.class, () -> context.readExternal(mock(ObjectInput.class)));
    }

    @Test
    void should_not_print_value_in_toString() {
        assertEquals("***** SENSITIVE VALUE *****", context().toString());
    }

    @SuppressWarnings("ALL")
    @Test
    void should_not_respect_equals() {
        final var context = context();

        assertFalse(context.equals(context));
        assertFalse(context.equals(context()));
    }

    @Test
    void should_not_respect_hash_code() {
        final var context = context();

        assertEquals(0, context.hashCode());
        assertEquals(context.hashCode(), context().hashCode());
    }

    private Context context() {
        return gcm(new Secret(secretKey()), new AAD("some aad data")).encryption();
    }
}