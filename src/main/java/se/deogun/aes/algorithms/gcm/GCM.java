package se.deogun.aes.algorithms.gcm;

import se.deogun.aes.algorithms.AES;
import se.deogun.aes.algorithms.AESRejectReason;
import se.deogun.aes.algorithms.Result;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.algorithms.AESRejectReason.*;
import static se.deogun.aes.algorithms.Result.*;

public final class GCM implements AES {
    private final GCMContext context;

    public GCM(final GCMContext context) {
        this.context = notNull(context);
    }

    @Override
    public final Result<Throwable, byte[], AESRejectReason> encrypt(final byte[] data) {
        notNull(data);

        try {
            return process(data, ENCRYPT_MODE);
        } catch (GCMLimitViolation e) {
            return reject(ENCRYPTION_LIMIT_EXCEEDED);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_ENCRYPT_DATA);
        }
    }

    @Override
    public final Result<Throwable, byte[], AESRejectReason> decrypt(final byte[] data) {
        notNull(data);

        try {
            return process(data, DECRYPT_MODE);
        } catch (GCMLimitViolation e) {
            return reject(DECRYPTION_LIMIT_EXCEEDED);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            return reject(UNABLE_TO_DECRYPT_DATA);
        }
    }

    private Result<Throwable, byte[], AESRejectReason> process(final byte[] data, final int mode) throws BadPaddingException, IllegalBlockSizeException {
        try {
            final var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, context.secret(), context.parameters());
            cipher.updateAAD(context.aad());

            return accept(cipher.doFinal(data));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return reject(AES_GCM_NOT_AVAILABLE_ON_THIS_SYSTEM);
        } catch (InvalidKeyException e) {
            return reject(INVALID_GCM_KEY);
        } catch (InvalidAlgorithmParameterException e) {
            return reject(INVALID_GCM_PARAMETERS);
        }
    }
}
