package se.deogun.aes.modes.gcm;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;
import se.deogun.aes.modes.Secret;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.modes.AESRejectReason.UNABLE_TO_DECRYPT_DATA;
import static se.deogun.aes.modes.AESRejectReason.UNABLE_TO_ENCRYPT_DATA;
import static se.deogun.aes.modes.Result.*;

public final class GCM {
    public final Result<Throwable, byte[], AESRejectReason> encrypt(final byte[] data, final Secret secret, final AAD aad) {
        notNull(data);
        notNull(secret);
        notNull(aad);

        try {
            final var iv = new byte[12];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final var parameters = new GCMParameterSpec(128, iv);

            cipher.init(ENCRYPT_MODE, secret.keySpecification(), parameters);
            cipher.updateAAD(aad.value());
            final var cipherText = cipher.doFinal(data);

            final var byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);
            return accept(byteBuffer.array());
            //return process(data, ENCRYPT_MODE);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_ENCRYPT_DATA);
        } catch (Exception e) {
            return failure(e);
        }
    }

    public final Result<Throwable, byte[], AESRejectReason> decrypt(final byte[] data, final Secret secret, final AAD aad) {
        notNull(data);
        notNull(secret);
        notNull(aad);

        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            AlgorithmParameterSpec spec = new GCMParameterSpec(128, data, 0, 12);
            cipher.init(DECRYPT_MODE, secret.keySpecification(), spec);
            cipher.updateAAD(aad.value());
            return accept(cipher.doFinal(data, 12, data.length - 12));

            //  return process(data, DECRYPT_MODE);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_DECRYPT_DATA);
        } catch (Exception e) {
            return failure(e);
        }
    }

//    private Result<Throwable, byte[], AESRejectReason> process(final byte[] data, final int mode) throws BadPaddingException, IllegalBlockSizeException {
//        try {
//            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
//            cipher.init(mode, context.secret(), context.parameters());
//            cipher.updateAAD(context.aad());
//
//            return accept(cipher.doFinal(data));
//
//        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
//            return reject(AES_GCM_NOT_AVAILABLE_ON_THIS_SYSTEM);
//        } catch (InvalidKeyException e) {
//            return reject(INVALID_GCM_KEY);
//        } catch (InvalidAlgorithmParameterException e) {
//            return reject(INVALID_GCM_PARAMETERS);
//        }
//    }
}
