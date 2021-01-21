package se.deogun.aes;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.InternalValidationFailure;
import se.deogun.aes.modes.Result;
import se.deogun.aes.modes.AAD;
import se.deogun.aes.modes.gcm.GCM;
import se.deogun.aes.modes.Secret;

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
     * @param secret secret key
     * @return AES GCM service
     */
    public static AES aesGCM(final Secret secret) {
        notNull(secret);

        return new AES() {
            @Override
            public Result<? super AESFailure, byte[], AESRejectReason> encrypt(final byte[] plain, final AAD aad) {
                notNull(plain);
                notNull(aad);
                return apply(() -> new GCM().encrypt(plain, secret, aad));
            }

            @Override
            public Result<? super AESFailure, OutputStream, AESRejectReason> encrypt(final byte[] plain, final OutputStream outputStream, final AAD aad) {
                notNull(plain);
                notNull(outputStream);
                notNull(aad);
                return apply(() -> new GCM().encrypt(plain, outputStream, secret, aad));
            }

            @Override
            public Result<? super AESFailure, byte[], AESRejectReason> decrypt(final byte[] encrypted, final AAD aad) {
                notNull(encrypted);
                notNull(aad);
                return apply(() -> new GCM().decrypt(encrypted, secret, aad));
            }

            @Override
            public Result<? super AESFailure, byte[], AESRejectReason> decrypt(final InputStream inputStream, final AAD aad) {
                notNull(inputStream);
                notNull(aad);
                return apply(() -> new GCM().decrypt(inputStream, secret, aad));
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
