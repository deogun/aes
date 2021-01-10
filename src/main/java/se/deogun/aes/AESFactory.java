package se.deogun.aes;

import se.deogun.aes.modes.AES;
import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;
import se.deogun.aes.modes.Secret;
import se.deogun.aes.modes.gcm.AAD;
import se.deogun.aes.modes.gcm.GCM;
import se.deogun.aes.modes.gcm.GCMContext;

import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.modes.Result.failure;

/**
 * Factory to create different AES modes
 */
public final class AESFactory {

    /**
     * Creates an AES instance with GCM mode
     * @param secret secret key
     * @param aad additional authentication data
     * @return AES GCM instance
     */
    public static AES aesGCM(final Secret secret, final AAD aad) {
        notNull(secret);
        notNull(aad);

        return new AES() {
            @Override
            public final Result<Throwable, byte[], AESRejectReason> encrypt(final byte[] data) {
                notNull(data);

                try {
                    return new GCM().encrypt(data, secret, aad);
                } catch (Throwable e) {
                    return failure(new AESFailure(e.getClass()));
                }
            }

            @Override
            public final Result<Throwable, byte[], AESRejectReason> decrypt(final byte[] data) {
                notNull(data);

                try {
                    return new GCM().decrypt(data, secret, aad);
                } catch (Throwable e) {
                    return failure(new AESFailure(e.getClass()));
                }
            }
        };
    }
}
