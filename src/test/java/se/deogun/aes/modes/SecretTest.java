package se.deogun.aes.modes;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.gcm.Secret;

import java.io.ObjectInput;
import java.io.ObjectOutput;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static se.deogun.aes.modes.SecretKeyFactory.nonBase64EncodedKey;
import static se.deogun.aes.modes.SecretKeyFactory.secretKey;

class SecretTest {
    static final byte[] SECRET_KEY_1 = secretKey();
    static final byte[] SECRET_KEY_2 = secretKey();

    @Test
    void should_require_base64_encoded_key() {
        assertThrows(IllegalArgumentException.class, () -> new Secret(nonBase64EncodedKey()));
    }

    @Test
    void should_accept_base64_encoded_key() {
        assertDoesNotThrow(() -> new Secret(SECRET_KEY_1));
    }

    @Test
    void should_accept_base64_encoded_string_key() {
        assertDoesNotThrow(() -> new Secret(new String(SECRET_KEY_1)));
    }

    @Test
    void should_not_allow_externalization() {
        final var secret = new Secret(SECRET_KEY_1);

        assertThrows(UnsupportedOperationException.class, () -> secret.writeExternal(mock(ObjectOutput.class)));
        assertThrows(UnsupportedOperationException.class, () -> secret.readExternal(mock(ObjectInput.class)));
    }

    @Test
    void should_not_print_value_in_toString() {
        final var result = new Secret(SECRET_KEY_1).toString();

        assertEquals("***** SENSITIVE VALUE *****", result);
    }

    @SuppressWarnings("ALL")
    @Test
    void should_not_respect_equals() {
        final Secret secret = new Secret(SECRET_KEY_1);
        assertFalse(secret.equals(secret));
        assertFalse(secret.equals(new Secret(SECRET_KEY_2)));
    }

    @Test
    void should_not_respect_hash_code() {
        final Secret secret = new Secret(SECRET_KEY_1);

        assertEquals(0, secret.hashCode());
        assertEquals(secret.hashCode(), new Secret(SECRET_KEY_2).hashCode());
    }
}