package se.deogun.aes;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import se.deogun.aes.api.AES;
import se.deogun.aes.api.Secret;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static org.junit.jupiter.api.Assertions.*;
import static se.deogun.aes.api.RejectReason.UNABLE_TO_DECRYPT_DATA;
import static se.deogun.aes.api.Secret.secretFromBase64EncodedKey;
import static se.deogun.aes.modes.common.SecretKeyFactory.base64EncodedKey;

class CBCIntegrationTest {
    @Test
    void should_be_encrypted() {
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encrypted = cbc(secretFromBase64EncodedKey(base64EncodedKey())).encrypt(data).liftAccept();

        assertFalse(Arrays.equals(data, encrypted));
    }

    @Test
    void should_not_produce_same_encrypted_output_twice() {
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);

        final var encryptedData1 = cbc(secretFromBase64EncodedKey(base64EncodedKey())).encrypt(data).liftAccept();
        final var encryptedData2 = cbc(secretFromBase64EncodedKey(base64EncodedKey())).encrypt(data).liftAccept();

        assertFalse(Arrays.equals(encryptedData1, encryptedData2));
    }

    @Test
    void should_produce_the_same_output() {
        final var data = randomAlphanumeric(100000).getBytes(UTF_8);
        final var secret = secretFromBase64EncodedKey(base64EncodedKey());

        final var decrypted1 = cbc(secret).decrypt(cbc(secret).encrypt(data).liftAccept()).liftAccept();
        final var decrypted2 = cbc(secret).decrypt(cbc(secret).encrypt(data).liftAccept()).liftAccept();

        assertArrayEquals(decrypted1, decrypted2);
    }

    @Test
    void should_support_streams() {
        final var data = randomAlphabetic(100000).getBytes(UTF_8);
        final var outputStream = new ByteArrayOutputStream();
        final var secret = secretFromBase64EncodedKey(base64EncodedKey());

        cbc(secret).encrypt(data, outputStream);
        final var result = cbc(secret).decrypt(new ByteArrayInputStream(outputStream.toByteArray())).liftAccept();

        assertArrayEquals(data, result);
    }

    @Test
    void should_fail_to_decrypt_because_of_wrong_secret() {
        final var secret1 = secretFromBase64EncodedKey(base64EncodedKey());
        final var secret2 = secretFromBase64EncodedKey(base64EncodedKey());
        final var encrypted = cbc(secret1).encrypt(randomAlphanumeric(100000).getBytes(UTF_8)).liftAccept();

        cbc(secret2)
                .decrypt(encrypted)
                .handle(success -> success
                        .accept(value -> fail("unexpected successful decryption"))
                        .reject(value -> assertEquals(UNABLE_TO_DECRYPT_DATA, value)))
                .or(failure -> fail("unexpected exception"));
    }

    @Test
    void should_use_stored_secret_to_encrypt_decrypt() throws IOException {
        final var storedSecret = Files.readAllBytes(Paths.get("src", "test", "resources", "secret.b64enc"));
        final var secret = secretFromBase64EncodedKey(storedSecret);
        final var secretMessage = "This is my secret message";

        final var encryptedMessage = cbc(secret).encrypt(secretMessage.getBytes(UTF_8)).liftAccept();
        assertNotEquals(secretMessage, new String(encryptedMessage));

        final var decryptedMessage = cbc(secret).decrypt(encryptedMessage).liftAccept();
        assertEquals(secretMessage, new String(decryptedMessage));
    }

    private static AES cbc(final Secret secret) {
        return AESFactory.aesCBC(secret);
    }
}
