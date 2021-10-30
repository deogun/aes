package se.deogun.aes.modes;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.common.AAD;
import se.deogun.aes.modes.common.Secret;

import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.junit.jupiter.api.Assertions.*;
import static se.deogun.aes.modes.common.AAD.NO_AAD;
import static se.deogun.aes.modes.common.SecretKeyFactory.key;

class CBCTest {
    @Test
    void should_encrypt_decrypt_array_of_data() {
        final var data = randomAlphabetic(100000);
        final var secret = new Secret(key());

        final var encrypted = new CBC().encrypt(data.getBytes(UTF_8), secret);
        assertFalse(Arrays.equals(data.getBytes(UTF_8), encrypted.liftAccept()));

        new CBC().decrypt(encrypted.liftAccept(), secret)
                .handle(success -> success
                        .accept(decrypted -> assertEquals(data, new String(decrypted)))
                        .reject(reason -> fail("Decryption Rejected: " + reason)))
                .or(failure -> {
                    failure.printStackTrace();
                    fail("Failure: " + failure.getMessage());
                });
    }
}