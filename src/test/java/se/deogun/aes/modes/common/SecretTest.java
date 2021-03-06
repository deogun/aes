package se.deogun.aes.modes.common;

import org.junit.jupiter.api.Test;

import java.io.ObjectInput;
import java.io.ObjectOutput;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static se.deogun.aes.modes.common.SecretKeyFactory.key;

class SecretTest {

    @Test
    void should_clone_key() {
        var key = key();
        final var secret = new Secret(key);
        final var keySpecification = secret.keySpecification();
        key[0]++;

        assertEquals(keySpecification, secret.keySpecification());
    }

    @Test
    void should_not_allow_externalization() {
        final var secret = new Secret(key());

        assertThrows(UnsupportedOperationException.class, () -> secret.writeExternal(mock(ObjectOutput.class)));
        assertThrows(UnsupportedOperationException.class, () -> secret.readExternal(mock(ObjectInput.class)));
    }

    @Test
    void should_not_print_value_in_toString() {
        final var result = new Secret(key()).toString();

        assertEquals("***** SENSITIVE VALUE *****", result);
    }

    @SuppressWarnings("ALL")
    @Test
    void should_not_respect_equals() {
        final Secret secret = new Secret(key());

        assertFalse(secret.equals(secret));
        assertFalse(secret.equals(new Secret(key())));
    }

    @Test
    void should_not_respect_hash_code() {
        final Secret secret = new Secret(key());

        assertEquals(0, secret.hashCode());
        assertEquals(secret.hashCode(), new Secret(key()).hashCode());
    }
}