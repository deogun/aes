package se.deogun.aes.modes;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import se.deogun.aes.modes.common.AAD;
import se.deogun.aes.modes.common.InternalRejectReason;
import se.deogun.aes.modes.common.Result;
import se.deogun.aes.modes.common.Secret;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.fail;
import static se.deogun.aes.modes.common.SecretKeyFactory.key;

public class EncryptDecryptTest {
    private static final Map<String, Proxy> ALGORITHMS = Map.of(
            "GCM", new GCMProxy(16),
            "CBC", new CBCProxy(16)
    );

    @ParameterizedTest
    @ValueSource(strings = {"GCM", "CBC"})
    public void should_encrypt_byte_array(final String type) {
        final var data = randomAlphabetic(100000);
        final var secret = new Secret(key());
        final var aad = new AAD("some aad");

        final var encryptedResult = ALGORITHMS.get(type).encrypt(data.getBytes(UTF_8), secret, aad);
        assertFalse(Arrays.equals(data.getBytes(UTF_8), encryptedResult.liftAccept()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GCM", "CBC"})
    public void should_decrypt_byte_array(final String type) {
        final var data = randomAlphabetic(100000);
        final var secret = new Secret(key());
        final var aad = new AAD("some aad");

        ALGORITHMS.get(type)
                .decrypt(ALGORITHMS.get(type).encrypt(data.getBytes(UTF_8), secret, aad).liftAccept(),secret, aad)
                .handle(success -> success
                        .accept(decrypted -> assertEquals(data, new String(decrypted)))
                        .reject(reason -> fail("Decryption Rejected: " + reason)))
                .or(failure -> {
                    failure.printStackTrace();
                    fail("Failure: " + failure.getMessage());
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"GCM"})
    void should_support_encrypt_stream(final String type) {
        final var data = randomAlphabetic(100000);
        final var outputStream = new ByteArrayOutputStream();
        final var secret = new Secret(key());
        final var aad = new AAD("some aad");

        ALGORITHMS.get(type).encrypt(data.getBytes(UTF_8), outputStream, secret, aad);
        assertFalse(Arrays.equals(data.getBytes(UTF_8), outputStream.toByteArray()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GCM"})
    void should_support_decrypt_stream(final String type) {
        final var data = randomAlphabetic(100000);
        final var outputStream = new ByteArrayOutputStream();
        final var secret = new Secret(key());
        final var aad = new AAD("some aad");

        ALGORITHMS.get(type).encrypt(data.getBytes(UTF_8), outputStream, secret, aad);
        ALGORITHMS.get(type).decrypt(new ByteArrayInputStream(outputStream.toByteArray()), secret, aad)
                .handle(success -> success
                        .accept(decrypted -> assertEquals(data, new String(decrypted)))
                        .reject(reason -> fail("Decryption Rejected: " + reason)))
                .or(failure -> {
                    failure.printStackTrace();
                    fail("Failure: " + failure.getMessage());
                });
    }

    private interface Proxy {
        Result<Throwable, byte[], InternalRejectReason> encrypt(final byte[] plainText, final Secret secret, final AAD aad);
        Result<Throwable, OutputStream, InternalRejectReason> encrypt(final byte[] plainText, final OutputStream outputStream,
                                                                      final Secret secret, final AAD aad);
        Result<Throwable, byte[], InternalRejectReason> decrypt(byte[] encryptedData, Secret secret, AAD aad);
        Result<Throwable, byte[], InternalRejectReason> decrypt(final InputStream inputStream, final Secret secret, final AAD aad);
    }

    private static final class GCMProxy implements Proxy {
        private final int decryptBufferLoadSize;

        private GCMProxy(final int decryptBufferLoadSize) {
            this.decryptBufferLoadSize = decryptBufferLoadSize;
        }

        @Override
        public Result<Throwable, byte[], InternalRejectReason> encrypt(final byte[] plainText, final Secret secret, final AAD aad) {
            return new GCM(decryptBufferLoadSize).encrypt(plainText, secret, aad);
        }

        @Override
        public Result<Throwable, OutputStream, InternalRejectReason> encrypt(final byte[] plainText, final OutputStream outputStream, final Secret secret, final AAD aad) {
            return new GCM(decryptBufferLoadSize).encrypt(plainText, outputStream, secret, aad);
        }

        public Result<Throwable, byte[], InternalRejectReason> decrypt(final byte[] encryptedData, final Secret secret, final AAD aad) {
            return new GCM(decryptBufferLoadSize).decrypt(encryptedData, secret, aad);
        }

        @Override
        public Result<Throwable, byte[], InternalRejectReason> decrypt(final InputStream inputStream, final Secret secret, final AAD aad) {
            return new GCM(decryptBufferLoadSize).decrypt(inputStream, secret, aad);
        }
    }

    private static final class CBCProxy implements Proxy {
        private final int decryptBufferLoadSize;

        private CBCProxy(final int decryptBufferLoadSize) {
            this.decryptBufferLoadSize = decryptBufferLoadSize;
        }

        @Override
        public Result<Throwable, byte[], InternalRejectReason> encrypt(final byte[] plainText, final Secret secret, final AAD aad) {
            return new CBC(decryptBufferLoadSize).encrypt(plainText, secret);
        }

        @Override
        public Result<Throwable, OutputStream, InternalRejectReason> encrypt(final byte[] plainText, final OutputStream outputStream, final Secret secret, final AAD aad) {
            fail("not implemented yet");
            return null;
        }

        public Result<Throwable, byte[], InternalRejectReason> decrypt(final byte[] encryptedData, final Secret secret, final AAD aad) {
            return new CBC(decryptBufferLoadSize).decrypt(encryptedData, secret);
        }

        @Override
        public Result<Throwable, byte[], InternalRejectReason> decrypt(final InputStream inputStream, final Secret secret, final AAD aad) {
            fail("not implemented yet");
            return null;
        }
    }
}
