package se.deogun.aes.modes;

import se.deogun.aes.modes.common.InternalRejectReason;
import se.deogun.aes.modes.common.Result;
import se.deogun.aes.modes.common.Secret;
import se.deogun.aes.modes.common.UnableToCreateSecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
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
import static se.deogun.aes.api.Result.failure;
import static se.deogun.aes.modes.InternalValidation.isNotNull;
import static se.deogun.aes.modes.common.InternalRejectReason.*;
import static se.deogun.aes.modes.common.Result.accept;
import static se.deogun.aes.modes.common.Result.reject;

final class CBC implements NonAADMode {
    private static final int IV_NUMBER_OF_BYTES = 16;
    private static final int START_INDEX_OF_ENCRYPTED_DATA = 16;
    private static final int _16KB = 16 * 1024;
    private static final int END_OF_STREAM = -1;

    @Override
    public Result<Throwable, byte[], InternalRejectReason> encrypt(final byte[] plainText, final Secret secret) {
        isNotNull(plainText);
        isNotNull(secret);

        try {
            final var cipher = cbc();
            final var initVectorSpec = initVectorSpec();

            cipher.init(ENCRYPT_MODE, secret.keySpecification(), initVectorSpec);
            return accept(encryptedData(initVectorSpec.getIV(), cipher.doFinal(plainText)));

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            return reject(CBC_NOT_AVAILABLE);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(CBC_INVALID_PARAMETERS);
        } catch (InvalidKeyException e) {
            return reject(CBC_INVALID_KEY);
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
            return reject(UNABLE_TO_ENCRYPT);
        } catch (UnableToCreateSecureRandom unableToCreateSecureRandom) {
            return reject(NO_SECURE_RANDOM_ALGORITHM);
        }
    }

    @Override
    public Result<Throwable, byte[], InternalRejectReason> decrypt(final byte[] encryptedData, final Secret secret) {
        isNotNull(encryptedData);
        isNotNull(secret);

        try {
            final var cipher = cbc();
            final var iv = initVectorSpec(encryptedData);
            cipher.init(DECRYPT_MODE, secret.keySpecification(), iv);

            return accept(cipher.doFinal(encryptedData, START_INDEX_OF_ENCRYPTED_DATA, encryptedData.length - IV_NUMBER_OF_BYTES));

        } catch (InvalidAlgorithmParameterException e) {
            return reject(CBC_INVALID_PARAMETERS);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            return reject(CBC_NOT_AVAILABLE);
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
            return reject(UNABLE_TO_DECRYPT);
        } catch (InvalidKeyException e) {
            return reject(CBC_INVALID_KEY);
        }
    }

    @Override
    public Result<Throwable, OutputStream, InternalRejectReason> encrypt(final byte[] plainText,
                                                                         final OutputStream outputStream,
                                                                         final Secret secret) {
        isNotNull(plainText);
        isNotNull(outputStream);
        isNotNull(secret);

        try {
            final var encrypted = encrypt(plainText, secret);
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

    @Override
    public Result<Throwable, byte[], InternalRejectReason> decrypt(final InputStream encryptedData, final Secret secret) {
        isNotNull(encryptedData);
        isNotNull(secret);

        try {
            return decrypt(toBytes(encryptedData), secret);
        } catch (IOException e) {
            return reject(UNABLE_TO_DECRYPT);
        }
    }

    private byte[] toBytes(final InputStream stream) throws IOException {
        final var buffer = new ByteArrayOutputStream();
        final var data = new byte[_16KB];
        int read;

        while ((read = stream.read(data, 0, data.length)) != END_OF_STREAM) {
            buffer.write(data, 0, read);
        }
        return buffer.toByteArray();
    }

    private Cipher cbc() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    private byte[] encryptedData(final byte[] iv, final byte[] encrypted) {
        final var byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return byteBuffer.array();
    }

    private IvParameterSpec initVectorSpec(final byte[] encryptedData) {
        final var iv = new byte[IV_NUMBER_OF_BYTES];
        System.arraycopy(encryptedData, 0, iv, 0, IV_NUMBER_OF_BYTES);
        return new IvParameterSpec(iv);
    }

    private IvParameterSpec initVectorSpec() throws UnableToCreateSecureRandom {
        try {
            final var nonce = new byte[IV_NUMBER_OF_BYTES];
            SecureRandom.getInstanceStrong().nextBytes(nonce);
            return new IvParameterSpec(nonce);
        } catch (NoSuchAlgorithmException e) {
            throw new UnableToCreateSecureRandom();
        }
    }
}
