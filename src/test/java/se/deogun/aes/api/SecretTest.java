package se.deogun.aes.api;

import org.junit.jupiter.api.Test;

import java.io.ObjectInput;
import java.io.ObjectOutput;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static se.deogun.aes.api.Secret.*;
import static se.deogun.aes.modes.common.SecretKeyFactory.key;
import static se.deogun.aes.modes.common.SecretKeyFactory.base64EncodedKey;

class SecretTest {

    @Test
    void should_support_non_base64_encoded_key() {
        assertDoesNotThrow(() -> secretFromNonBase64EncodedKey(key()));
    }

    @Test
    void should_accept_base64_encoded_key() {
        assertDoesNotThrow(() -> secretFromBase64EncodedKey(base64EncodedKey()));
    }

    @Test
    void should_accept_base64_encoded_string_key() {
        assertDoesNotThrow(() -> secretFromBase64EncodedKey(new String(base64EncodedKey())));
    }

    @Test
    void should_accept_non_base64_encoded_string_key() {
        assertDoesNotThrow(() -> secretFromNonBase64EncodedKey(new String(key())));
    }

    @Test
    void should_contain_key() {
        final var key = key();
        final var secret = secretFromNonBase64EncodedKey(new String(key));

        assertArrayEquals(new String(key).getBytes(UTF_8), secret.key());
    }

    @Test
    void should_not_allow_externalization() {
        final var secret = secretFromNonBase64EncodedKey(key());

        assertThrows(UnsupportedOperationException.class, () -> secret.writeExternal(mock(ObjectOutput.class)));
        assertThrows(UnsupportedOperationException.class, () -> secret.readExternal(mock(ObjectInput.class)));
    }

    @Test
    void should_not_print_value_in_toString() {
        final var result = secretFromNonBase64EncodedKey(key()).toString();

        assertEquals("***** SENSITIVE VALUE *****", result);
    }

    @SuppressWarnings("ALL")
    @Test
    void should_not_respect_equals() {
        final Secret secret = secretFromNonBase64EncodedKey(key());

        assertFalse(secret.equals(secret));
        assertFalse(secret.equals(secretFromNonBase64EncodedKey(key())));
    }

    @Test
    void should_not_respect_hash_code() {
        final Secret secret = secretFromNonBase64EncodedKey(key());

        assertEquals(0, secret.hashCode());
        assertEquals(secret.hashCode(), secretFromNonBase64EncodedKey(key()).hashCode());
    }
}