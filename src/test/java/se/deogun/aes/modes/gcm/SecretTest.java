package se.deogun.aes.modes.gcm;

import org.junit.jupiter.api.Test;

import java.io.ObjectInput;
import java.io.ObjectOutput;

import static org.apache.commons.lang3.RandomStringUtils.random;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static se.deogun.aes.modes.gcm.SecretKeyFactory.nonBase64EncodedKey;
import static se.deogun.aes.modes.gcm.SecretKeyFactory.secretKey;
import static se.deogun.aes.modes.gcm.Secret.secret;
import static se.deogun.aes.modes.gcm.Secret.secretFromBase64EncodedKey;

class SecretTest {
    static final byte[] BASE64_ENCODED_SECRET_KEY_1 = secretKey();
    static final byte[] BASE64_ENCODED_SECRET_KEY_2 = secretKey();

    @Test
    void should_support_non_base64_encoded_key() {
        assertDoesNotThrow(() -> secret(nonBase64EncodedKey()));
    }

    @Test
    void should_accept_base64_encoded_key() {
        assertDoesNotThrow(() -> secretFromBase64EncodedKey(BASE64_ENCODED_SECRET_KEY_1));
    }

    @Test
    void should_accept_base64_encoded_string_key() {
        assertDoesNotThrow(() -> secretFromBase64EncodedKey(new String(BASE64_ENCODED_SECRET_KEY_1)));
    }

    @Test
    void should_not_allow_externalization() {
        final var secret = secretFromBase64EncodedKey(BASE64_ENCODED_SECRET_KEY_1);

        assertThrows(UnsupportedOperationException.class, () -> secret.writeExternal(mock(ObjectOutput.class)));
        assertThrows(UnsupportedOperationException.class, () -> secret.readExternal(mock(ObjectInput.class)));
    }

    @Test
    void should_not_print_value_in_toString() {
        final var result = secretFromBase64EncodedKey(BASE64_ENCODED_SECRET_KEY_1).toString();

        assertEquals("***** SENSITIVE VALUE *****", result);
    }

    @SuppressWarnings("ALL")
    @Test
    void should_not_respect_equals() {
        final Secret secret = secretFromBase64EncodedKey(BASE64_ENCODED_SECRET_KEY_1);

        assertFalse(secret.equals(secret));
        assertFalse(secret.equals(secretFromBase64EncodedKey(BASE64_ENCODED_SECRET_KEY_2)));
    }

    @Test
    void should_not_respect_hash_code() {
        final Secret secret = secret(nonBase64EncodedKey());

        assertEquals(0, secret.hashCode());
        assertEquals(secret.hashCode(), secret(nonBase64EncodedKey()).hashCode());
    }
}