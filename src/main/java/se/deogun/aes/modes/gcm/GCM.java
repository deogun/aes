package se.deogun.aes.modes.gcm;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.modes.AESRejectReason.*;
import static se.deogun.aes.modes.Result.accept;
import static se.deogun.aes.modes.Result.reject;

public final class GCM {
    private static final int START_INDEX_OF_ENCRYPTED_DATA = 12;
    private static final int TAG_LENGTH_IN_BITS = 128;
    private static final int START_INDEX_OF_IV = 0;
    private static final int NUMBER_OF_IV_BYTES = 12;
    private static final int IV_NUMBER_OF_BYTES = 12;
    private static final int _16KB = 16 * 1024;
    private static final int END_OF_STREAM = -1;

    static final class UnableToCreateSecureRandom extends Exception {
    }

    public final Result<Throwable, OutputStream, AESRejectReason> encrypt(final byte[] plainText, final OutputStream outputStream,
                                                                          final Secret secret, final AAD aad) {
        notNull(plainText);
        notNull(outputStream);
        notNull(secret);
        notNull(aad);

        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final byte[] initVector = initVector();
            final var gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, initVector);

            cipher.init(ENCRYPT_MODE, secret.keySpecification(), gcmParameterSpec);
            cipher.updateAAD(aad.value());

            try (var cos = new CipherOutputStream(outputStream, cipher)) {
                outputStream.write(initVector);
                cos.write(plainText);
            }
            return accept(outputStream);

        } catch (UnableToCreateSecureRandom e) {
            return reject(NO_SECURE_RANDOM_ALGORITHM_AVAILABLE_ON_THIS_SYSTEM);
        } catch (IOException | IllegalStateException e) {
            return reject(UNABLE_TO_ENCRYPT_DATA);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return reject(AES_GCM_NOT_AVAILABLE_ON_THIS_SYSTEM);
        } catch (InvalidKeyException e) {
            return reject(INVALID_GCM_KEY);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(INVALID_GCM_PARAMETERS);
        }
    }

    public final Result<Throwable, byte[], AESRejectReason> encrypt(final byte[] plainText, final Secret secret, final AAD aad) {
        notNull(plainText);
        notNull(secret);
        notNull(aad);

        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final byte[] initVector = initVector();
            final var gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, initVector);

            cipher.init(ENCRYPT_MODE, secret.keySpecification(), gcmParameterSpec);
            cipher.updateAAD(aad.value());

            return accept(encryptedData(initVector, cipher.doFinal(plainText)));

        } catch (UnableToCreateSecureRandom e) {
            return reject(NO_SECURE_RANDOM_ALGORITHM_AVAILABLE_ON_THIS_SYSTEM);
        } catch (IllegalStateException | BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_ENCRYPT_DATA);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return reject(AES_GCM_NOT_AVAILABLE_ON_THIS_SYSTEM);
        } catch (InvalidKeyException e) {
            return reject(INVALID_GCM_KEY);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(INVALID_GCM_PARAMETERS);
        }
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    public final Result<Throwable, byte[], AESRejectReason> decrypt(final InputStream inputStream, final Secret secret, final AAD aad) {
        notNull(inputStream);
        notNull(secret);
        notNull(aad);

        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final var iv = new byte[IV_NUMBER_OF_BYTES];
            inputStream.read(iv);
            final var gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, iv);

            cipher.init(DECRYPT_MODE, secret.keySpecification(), gcmParameterSpec);
            cipher.updateAAD(aad.value());

            try (final var cipherInputStream = new CipherInputStream(inputStream, cipher);
                 final var inputReader = new InputStreamReader(cipherInputStream, UTF_8);
                 final var encryptedData = new BufferedReader(inputReader)
            ) {
                return accept(decrypt(encryptedData));
            }
        } catch (IOException | IllegalStateException e) {
            return reject(UNABLE_TO_DECRYPT_DATA);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return reject(AES_GCM_NOT_AVAILABLE_ON_THIS_SYSTEM);
        } catch (InvalidKeyException e) {
            return reject(INVALID_GCM_KEY);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(INVALID_GCM_PARAMETERS);
        }
    }

    public final Result<Throwable, byte[], AESRejectReason> decrypt(final byte[] encryptedData, final Secret secret, final AAD aad) {
        notNull(encryptedData);
        notNull(secret);
        notNull(aad);

        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final var gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, encryptedData, START_INDEX_OF_IV, NUMBER_OF_IV_BYTES);

            cipher.init(DECRYPT_MODE, secret.keySpecification(), gcmParameterSpec);
            cipher.updateAAD(aad.value());

            return accept(cipher.doFinal(encryptedData, START_INDEX_OF_ENCRYPTED_DATA, encryptedData.length - IV_NUMBER_OF_BYTES));

        } catch (IllegalStateException | BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_DECRYPT_DATA);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return reject(AES_GCM_NOT_AVAILABLE_ON_THIS_SYSTEM);
        } catch (InvalidKeyException e) {
            return reject(INVALID_GCM_KEY);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(INVALID_GCM_PARAMETERS);
        }
    }

    private byte[] decrypt(final BufferedReader reader) throws IOException {
        final var buffer = new char[_16KB];
        final var builder = new StringBuilder();
        int numberOfCharacters;

        while ((numberOfCharacters = reader.read(buffer, 0, buffer.length)) != END_OF_STREAM) {
            builder.append(buffer, 0, numberOfCharacters);
        }
        return builder.toString().getBytes(UTF_8);
    }

    private byte[] initVector() throws UnableToCreateSecureRandom {
        try {
            final var nonce = new byte[IV_NUMBER_OF_BYTES];
            SecureRandom.getInstanceStrong().nextBytes(nonce);
            return nonce;
        } catch (NoSuchAlgorithmException e) {
            throw new UnableToCreateSecureRandom();
        }
    }

    private byte[] encryptedData(final byte[] iv, final byte[] encrypted) {
        final var byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return byteBuffer.array();
    }
}