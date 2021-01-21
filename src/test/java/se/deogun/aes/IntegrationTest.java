package se.deogun.aes;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.AAD;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static org.junit.jupiter.api.Assertions.*;
import static se.deogun.aes.AESFactory.aesGCM;
import static se.deogun.aes.modes.AESRejectReason.UNABLE_TO_DECRYPT_DATA;
import static se.deogun.aes.modes.Secret.secret;
import static se.deogun.aes.modes.SecretKeyFactory.nonBase64EncodedKey;

class IntegrationTest {
    @Test
    void should_not_produce_same_output_twice() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var aes = aesGCM(secret(nonBase64EncodedKey()));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encryptedData1 = aes.encrypt(data, aad).liftAccept();
        final var encryptedData2 = aes.encrypt(data, aad).liftAccept();

        Arrays.sort(encryptedData1);
        Arrays.sort(encryptedData2);

        assertFalse(Arrays.equals(encryptedData1, encryptedData2));
    }

    @Test
    void should_produce_different_encryption_result() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var aes = aesGCM(secret(nonBase64EncodedKey()));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encryptedData1 = aes.encrypt(data, aad).liftAccept();
        final var encryptedData2 = aes.encrypt(data, new AAD(randomAlphabetic(10))).liftAccept();

        Arrays.sort(encryptedData1);
        Arrays.sort(encryptedData2);

        assertFalse(Arrays.equals(encryptedData1, encryptedData2));
    }

    @Test
    void should_decrypt_to_the_same_output() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var aes = aesGCM(secret(nonBase64EncodedKey()));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var decrypted1 = aes.decrypt(aes.encrypt(data, aad).liftAccept(), aad).liftAccept();
        final var decrypted2 = aes.decrypt(aes.encrypt(data, aad).liftAccept(), aad).liftAccept();

        assertArrayEquals(decrypted1, decrypted2);
    }

    @Test
    void should_support_streams() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var data = randomAlphabetic(100000).getBytes(UTF_8);
        final var outputStream = new ByteArrayOutputStream();
        final var aes = aesGCM(secret(nonBase64EncodedKey()));

        aes.encrypt(data, outputStream, aad).liftAccept();
        final var result = aes.decrypt(new ByteArrayInputStream(outputStream.toByteArray()), aad).liftAccept();

        assertArrayEquals(data, result);
    }

    @Test
    void should_be_encrypted() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var aes = aesGCM(secret(nonBase64EncodedKey()));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encrypted = aes.encrypt(data, aad).liftAccept();

        Arrays.sort(encrypted);
        Arrays.sort(data);

        assertFalse(Arrays.equals(data, encrypted));
    }

    @Test
    void should_fail_decryption() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var aes = aesGCM(secret(nonBase64EncodedKey()));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encrypted = aes.encrypt(data, aad).liftAccept();

        aes.decrypt(encrypted, new AAD(randomAlphabetic(10)))
                .handle(success -> success
                        .accept(value -> fail("unexpected successful decryption"))
                        .reject(value -> assertEquals(UNABLE_TO_DECRYPT_DATA, value)))
                .or(failure -> fail("unexpected exception"));
    }
}
