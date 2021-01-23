package se.deogun.aes;

import se.deogun.aes.modes.*;
import se.deogun.aes.modes.cipher.AAD;
import se.deogun.aes.modes.cipher.Secret;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Supplier;

import static se.deogun.aes.modes.Result.failure;

/**
 * Factory to create different AES modes
 */
public final class AESFactory {

    /**
     * Creates an AES instance with GCM mode
     *
     * @param secret secret to be used for encryption / decryption
     * @return AES GCM service
     */
    public static AES aesGCM(final Secret secret) {
        notNull(secret);
        return ModeFactory.gcm(mode -> aes(secret, mode));
    }

    private static AES aes(final Secret secret, final Mode mode) {
        return new AES() {
            @Override
            public Result<? super AESFailure, byte[], AESRejectReason> encrypt(final byte[] data, final AAD aad) {
                notNull(data);
                notNull(aad);

                return apply(() -> mode.encrypt(data, secret, aad));
            }

            @Override
            public Result<? super AESFailure, OutputStream, AESRejectReason> encrypt(final byte[] data, final OutputStream outputStream, final AAD aad) {
                notNull(data);
                notNull(outputStream);
                notNull(aad);

                return apply(() -> mode.encrypt(data, outputStream, secret, aad));
            }

            @Override
            public Result<? super AESFailure, byte[], AESRejectReason> decrypt(final byte[] data, final AAD aad) {
                notNull(data);
                notNull(aad);

                return apply(() -> mode.decrypt(data, secret, aad));
            }

            @Override
            public Result<? super AESFailure, byte[], AESRejectReason> decrypt(final InputStream inputStream, final AAD aad) {
                notNull(inputStream);
                notNull(aad);

                return apply(() -> mode.decrypt(inputStream, secret, aad));
            }
        };
    }

    private static <T> Result<? super AESFailure, T, AESRejectReason> apply(final Supplier<Result<Throwable, T, AESRejectReason>> operation) {
        try {
            return operation.get();
        } catch (InternalValidationFailure e) {
            return failure(new AESFailure(e));
        } catch (Throwable e) {
            return failure(new AESFailure(e.getClass()));
        }
    }

    private static void notNull(final Object input) {
        if (input == null) {
            throw new IllegalArgumentException("Null not allowed as input");
        }
    }
}
