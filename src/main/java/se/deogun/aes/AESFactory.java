package se.deogun.aes;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;
import se.deogun.aes.modes.gcm.Secret;
import se.deogun.aes.modes.gcm.AAD;
import se.deogun.aes.modes.gcm.GCM;

import java.util.function.Supplier;

import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.modes.Result.failure;

/**
 * Factory to create different AES modes
 */
public final class AESFactory {

    /**
     * Creates an AES instance with GCM mode
     *
     * @param secret secret key
     * @param aad    additional authentication data
     * @return AES GCM instance
     */
    public static AES aesGCM(final Secret secret, final AAD aad) {
        notNull(secret);
        notNull(aad);

        return new AES() {
            @Override
            public final Result<? super AESFailure, byte[], AESRejectReason> encrypt(final byte[] data) {
                notNull(data);
                return apply(() -> new GCM().encrypt(data, secret, aad));
            }

            @Override
            public final Result<? super AESFailure, byte[], AESRejectReason> decrypt(final byte[] data) {
                notNull(data);
                return apply(() -> new GCM().decrypt(data, secret, aad));
            }
        };
    }

    private static Result<? super AESFailure, byte[], AESRejectReason> apply(final Supplier<Result<Throwable, byte[], AESRejectReason>> operation) {
        try {
            return operation.get();
        } catch (Throwable e) {
            return failure(new AESFailure(e.getClass()));
        }
    }
}
