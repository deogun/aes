package se.deogun.aes.modes.gcm;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.modes.AESRejectReason.*;
import static se.deogun.aes.modes.Result.*;

public final class GCM {
    private static final int START_INDEX_OF_ENCRYPTED_DATA = 12;
    private static final int TAG_LENGTH_IN_BITS = 128;
    private static final int START_INDEX_OF_IV = 0;
    private static final int NUMBER_OF_IV_BYTES = 12;

    private static final class UnableToCreateSecureRandom extends Exception {
    }

    public final Result<Throwable, byte[], AESRejectReason> encrypt(final byte[] data, final Secret secret, final AAD aad) {
        notNull(data);
        notNull(secret);
        notNull(aad);

        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final byte[] initVector = initVector();

            cipher.init(ENCRYPT_MODE, secret.keySpecification(), new GCMParameterSpec(TAG_LENGTH_IN_BITS, initVector));
            cipher.updateAAD(aad.value());

            return accept(encryptedData(initVector, cipher.doFinal(data)));

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

    public final Result<Throwable, byte[], AESRejectReason> decrypt(final byte[] data, final Secret secret, final AAD aad) {
        notNull(data);
        notNull(secret);
        notNull(aad);

        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(DECRYPT_MODE, secret.keySpecification(), new GCMParameterSpec(TAG_LENGTH_IN_BITS, data, START_INDEX_OF_IV, NUMBER_OF_IV_BYTES));
            cipher.updateAAD(aad.value());

            return accept(cipher.doFinal(data, START_INDEX_OF_ENCRYPTED_DATA, data.length - 12));

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

    private byte[] initVector() throws UnableToCreateSecureRandom {
        try {
            final var nonce = new byte[12];
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