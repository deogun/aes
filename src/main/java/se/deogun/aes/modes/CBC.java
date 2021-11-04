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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static se.deogun.aes.modes.InternalValidation.isNotNull;
import static se.deogun.aes.modes.common.InternalRejectReason.*;
import static se.deogun.aes.modes.common.Result.accept;
import static se.deogun.aes.modes.common.Result.reject;

final class CBC implements NonAADMode {
    private static final int IV_NUMBER_OF_BYTES = 16;
    private static final int START_INDEX_OF_ENCRYPTED_DATA = 16;

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
            final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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
    public Result<Throwable, OutputStream, InternalRejectReason> encrypt(final byte[] plainText, final OutputStream outputStream, final Secret secret) {
        return null; //TODO Add implementation
    }

    @Override
    public Result<Throwable, byte[], InternalRejectReason> decrypt(final InputStream encryptedData, final Secret secret) {
        return null; //TODO Add implementation
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
