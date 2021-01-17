package se.deogun.aes;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.gcm.AAD;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static org.junit.jupiter.api.Assertions.*;
import static se.deogun.aes.AESFactory.aesGCM;
import static se.deogun.aes.modes.AESRejectReason.UNABLE_TO_DECRYPT_DATA;
import static se.deogun.aes.modes.gcm.Secret.secret;
import static se.deogun.aes.modes.gcm.SecretKeyFactory.nonBase64EncodedKey;

class IntegrationTest {
    @Test
    void should_not_produce_same_output_twice() {
        final var aes = aesGCM(secret(nonBase64EncodedKey()), new AAD(randomAlphanumeric(8192)));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encryptedData1 = aes.encrypt(data).liftAccept();
        final var encryptedData2 = aes.encrypt(data).liftAccept();

        Arrays.sort(encryptedData1);
        Arrays.sort(encryptedData2);

        assertFalse(Arrays.equals(encryptedData1, encryptedData2));
    }

    @Test
    void should_produce_different_encryption_result() {
        final var aes = aesGCM(secret(nonBase64EncodedKey()), new AAD(randomAlphanumeric(8192)));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encryptedData1 = aes.encrypt(data).liftAccept();
        final var encryptedData2 = aes.encrypt(data, new AAD(randomAlphabetic(10))).liftAccept();

        Arrays.sort(encryptedData1);
        Arrays.sort(encryptedData2);

        assertFalse(Arrays.equals(encryptedData1, encryptedData2));
    }

    @Test
    void should_decrypt_to_the_same_output() {
        final var aes = aesGCM(secret(nonBase64EncodedKey()), new AAD(randomAlphanumeric(8192)));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var decrypted1 = aes.decrypt(aes.encrypt(data).liftAccept()).liftAccept();
        final var decrypted2 = aes.decrypt(aes.encrypt(data).liftAccept()).liftAccept();

        assertArrayEquals(decrypted1, decrypted2);
    }

    @Test
    void should_support_streams() {
        final var data = randomAlphabetic(100000).getBytes(UTF_8);
        final var outputStream = new ByteArrayOutputStream();
        final var aes = aesGCM(secret(nonBase64EncodedKey()), new AAD(randomAlphanumeric(8192)));

        aes.encrypt(data, outputStream).liftAccept();
        final var result = aes.decrypt(new ByteArrayInputStream(outputStream.toByteArray())).liftAccept();

        assertArrayEquals(data, result);
    }

    @Test
    void should_be_encrypted() {
        final var aes = aesGCM(secret(nonBase64EncodedKey()), new AAD(randomAlphanumeric(8192)));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encrypted = aes.encrypt(data).liftAccept();

        Arrays.sort(encrypted);
        Arrays.sort(data);

        assertFalse(Arrays.equals(data, encrypted));
    }

    @Test
    void should_fail_decryption() {
        final var aes = aesGCM(secret(nonBase64EncodedKey()), new AAD(randomAlphanumeric(8192)));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encrypted = aes.encrypt(data).liftAccept();

        aes.decrypt(encrypted, new AAD(randomAlphabetic(10)))
                .handle(success -> success
                        .accept(value -> fail("unexpected successful decryption"))
                        .reject(value -> assertEquals(UNABLE_TO_DECRYPT_DATA, value)))
                .or(failure -> fail("unexpected exception"));
    }
}
