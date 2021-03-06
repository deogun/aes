package se.deogun.aes.modes;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.common.AAD;
import se.deogun.aes.modes.common.Secret;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.junit.jupiter.api.Assertions.*;
import static se.deogun.aes.modes.common.SecretKeyFactory.key;

class GCMTest {

    @Test
    void should_support_encrypt_decrypt_of_input_output_streams() {
        final var data = randomAlphabetic(100000);
        final var outputStream = new ByteArrayOutputStream();
        final var secret = new Secret(key());
        final var aad = new AAD("some aad");

        new GCM().encrypt(data.getBytes(UTF_8), outputStream, secret, aad);
        assertFalse(Arrays.equals(data.getBytes(UTF_8), outputStream.toByteArray()));

        new GCM().decrypt(new ByteArrayInputStream(outputStream.toByteArray()), secret, aad)
                .handle(success -> success
                        .accept(decrypted -> assertEquals(data, new String(decrypted)))
                        .reject(reason -> fail("Decryption Rejected: " + reason)))
                .or(failure -> {
                    failure.printStackTrace();
                    fail("Failure: " + failure.getMessage());
                });
    }

    @Test
    void should_support_encrypt_decrypt_of_byte_array() {
        final var data = randomAlphabetic(100000);
        final var secret = new Secret(key());
        final var aad = new AAD("some aad");

        final var encrypted = new GCM().encrypt(data.getBytes(UTF_8), secret, aad);
        assertFalse(Arrays.equals(data.getBytes(UTF_8), encrypted.liftAccept()));

        new GCM().decrypt(encrypted.liftAccept(), secret, aad)
                .handle(success -> success
                        .accept(decrypted -> assertEquals(data, new String(decrypted)))
                        .reject(reason -> fail("Decryption Rejected: " + reason)))
                .or(failure -> {
                    failure.printStackTrace();
                    fail("Failure: " + failure.getMessage());
                });
    }
}