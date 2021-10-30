package se.deogun.aes;

import org.junit.jupiter.api.Test;
import se.deogun.aes.api.AAD;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static org.junit.jupiter.api.Assertions.*;
import static se.deogun.aes.api.RejectReason.UNABLE_TO_DECRYPT_DATA;
import static se.deogun.aes.api.Secret.secretFromBase64EncodedKey;
import static se.deogun.aes.modes.common.SecretKeyFactory.base64EncodedKey;

class IntegrationTest {
    @Test
    void should_be_encrypted() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);
        final var aes = AESFactory.aesGCM(secretFromBase64EncodedKey(base64EncodedKey()));

        final var encrypted = aes.encrypt(data, aad).liftAccept();

        assertFalse(Arrays.equals(data, encrypted));
    }

    @Test
    void should_not_produce_same_encrypted_output_twice() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);
        final var aes = AESFactory.aesGCM(secretFromBase64EncodedKey(base64EncodedKey()));

        final var encryptedData1 = aes.encrypt(data, aad).liftAccept();
        final var encryptedData2 = aes.encrypt(data, aad).liftAccept();

        assertFalse(Arrays.equals(encryptedData1, encryptedData2));
    }

    @Test
    void should_produce_the_same_output() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);
        final var aes = AESFactory.aesGCM(secretFromBase64EncodedKey(base64EncodedKey()));

        final var decrypted1 = aes.decrypt(aes.encrypt(data, aad).liftAccept(), aad).liftAccept();
        final var decrypted2 = aes.decrypt(aes.encrypt(data, aad).liftAccept(), aad).liftAccept();

        assertArrayEquals(decrypted1, decrypted2);
    }

    @Test
    void should_support_streams() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var data = randomAlphabetic(100000).getBytes(UTF_8);
        final var outputStream = new ByteArrayOutputStream();
        final var aes = AESFactory.aesGCM(secretFromBase64EncodedKey(base64EncodedKey()));

        aes.encrypt(data, outputStream, aad).liftAccept();
        final var result = aes.decrypt(new ByteArrayInputStream(outputStream.toByteArray()), aad).liftAccept();

        assertArrayEquals(data, result);
    }

    @Test
    void should_fail_to_decrypt_because_of_wrong_AAD() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var aes = AESFactory.aesGCM(secretFromBase64EncodedKey(base64EncodedKey()));

        final var encrypted = aes.encrypt(randomAlphanumeric(100000).getBytes(UTF_8), aad).liftAccept();

        aes.decrypt(encrypted, new AAD(randomAlphabetic(10)))
                .handle(success -> success
                        .accept(value -> fail("unexpected successful decryption"))
                        .reject(value -> assertEquals(UNABLE_TO_DECRYPT_DATA, value)))
                .or(failure -> fail("unexpected exception"));
    }

    @Test
    void should_fail_to_decrypt_because_of_wrong_secret() {
        final var aad = new AAD(randomAlphanumeric(8192));
        final var aes1 = AESFactory.aesGCM(secretFromBase64EncodedKey(base64EncodedKey()));
        final var aes2 = AESFactory.aesGCM(secretFromBase64EncodedKey(base64EncodedKey()));

        final var encrypted = aes1.encrypt(randomAlphanumeric(100000).getBytes(UTF_8), aad).liftAccept();

        aes2.decrypt(encrypted, aad)
                .handle(success -> success
                        .accept(value -> fail("unexpected successful decryption"))
                        .reject(value -> assertEquals(UNABLE_TO_DECRYPT_DATA, value)))
                .or(failure -> fail("unexpected exception"));
    }

    @Test
    void should_use_stored_secret_to_encrypt_decrypt() throws IOException {
        final var storedSecret = Files.readAllBytes(Paths.get("src","test","resources", "secret.b64enc"));
        final var aad = new AAD(randomAlphanumeric(8192));
        final var secret = secretFromBase64EncodedKey(storedSecret);
        final var aes = AESFactory.aesGCM(secret);
        final var secretMessage = "This is my secret message";

        final var encryptedMessage = aes.encrypt(secretMessage.getBytes(UTF_8), aad).liftAccept();
        assertNotEquals(secretMessage, new String(encryptedMessage));

        final var decryptedMessage = aes.decrypt(encryptedMessage, aad).liftAccept();
        assertEquals(secretMessage, new String(decryptedMessage));
    }
}
