package se.deogun.aes.modes;

import se.deogun.aes.modes.common.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static se.deogun.aes.modes.InternalValidation.*;
import static se.deogun.aes.modes.common.InternalRejectReason.*;
import static se.deogun.aes.modes.common.Result.accept;
import static se.deogun.aes.modes.common.Result.reject;

final class GCM implements AADMode {
    private static final int START_INDEX_OF_ENCRYPTED_DATA = 12;
    private static final int TAG_LENGTH_IN_BITS = 128;
    private static final int START_INDEX_OF_IV = 0;
    private static final int NUMBER_OF_IV_BYTES = 12;
    private static final int IV_NUMBER_OF_BYTES = 12;
    private static final int END_OF_STREAM = -1;
    private final int decryptBufferLoadSize;

    GCM(final int decryptBufferLoadSize) {
        isTrue(isInRange(decryptBufferLoadSize, 2, 1024));

        this.decryptBufferLoadSize = decryptBufferLoadSize * 1024; //buffer size in KB
    }

    public Result<Throwable, OutputStream, InternalRejectReason> encrypt(final byte[] plainText, final OutputStream outputStream,
                                                                         final Secret secret, final AAD aad) {
        isNotNull(plainText);
        isNotNull(outputStream);
        isNotNull(secret);
        isNotNull(aad);

        try {
            final var encrypted = encrypt(plainText, secret, aad);
            if (encrypted.isAccept()) {
                outputStream.write(encrypted.liftAccept());
            }
            return encrypted.transform(
                    accept -> accept(outputStream),
                    reject -> reject(reject),
                    failure -> Result.failure(failure)
            );
        } catch (IOException e) {
            return reject(UNABLE_TO_ENCRYPT);
        }
    }

    public Result<Throwable, byte[], InternalRejectReason> encrypt(final byte[] plainText, final Secret secret, final AAD aad) {
        isNotNull(plainText);
        isNotNull(secret);
        isNotNull(aad);

        try {
            final var cipher = gcm();
            final byte[] initVector = initVector();
            final var gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, initVector);

            cipher.init(ENCRYPT_MODE, secret.keySpecification(), gcmParameterSpec);
            cipher.updateAAD(aad.value());

            return accept(encryptedData(initVector, cipher.doFinal(plainText)));

        } catch (UnableToCreateSecureRandom e) {
            return reject(NO_SECURE_RANDOM_ALGORITHM);
        } catch (IllegalStateException | BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_ENCRYPT);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return reject(GCM_NOT_AVAILABLE);
        } catch (InvalidKeyException e) {
            return reject(GCM_INVALID_KEY);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(GCM_INVALID_PARAMETERS);
        }
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    public Result<Throwable, byte[], InternalRejectReason> decrypt(final InputStream encryptedData, final Secret secret, final AAD aad) {
        isNotNull(encryptedData);
        isNotNull(secret);
        isNotNull(aad);

        try {
            return decrypt(toBytes(encryptedData), secret, aad);
        } catch (IOException e) {
            return reject(UNABLE_TO_DECRYPT);
        }
    }

    public Result<Throwable, byte[], InternalRejectReason> decrypt(final byte[] encryptedData, final Secret secret, final AAD aad) {
        isNotNull(encryptedData);
        isNotNull(secret);
        isNotNull(aad);

        try {
            final var cipher = gcm();
            final var gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, encryptedData, START_INDEX_OF_IV, NUMBER_OF_IV_BYTES);

            cipher.init(DECRYPT_MODE, secret.keySpecification(), gcmParameterSpec);
            cipher.updateAAD(aad.value());

            return accept(cipher.doFinal(encryptedData, START_INDEX_OF_ENCRYPTED_DATA, encryptedData.length - IV_NUMBER_OF_BYTES));

        } catch (IllegalStateException | BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_DECRYPT);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return reject(GCM_NOT_AVAILABLE);
        } catch (InvalidKeyException e) {
            return reject(GCM_INVALID_KEY);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(GCM_INVALID_PARAMETERS);
        }
    }

    private Cipher gcm() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    private byte[] toBytes(final InputStream stream) throws IOException {
        final var buffer = new ByteArrayOutputStream();
        final var data = new byte[decryptBufferLoadSize];
        int read;

        while ((read = stream.read(data, 0, data.length)) != END_OF_STREAM) {
            buffer.write(data, 0, read);
        }
        return buffer.toByteArray();
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