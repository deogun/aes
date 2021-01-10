package se.deogun.aes;

import se.deogun.aes.modes.AES;
import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;
import se.deogun.aes.modes.gcm.GCM;
import se.deogun.aes.modes.gcm.GCMContext;

import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.modes.Result.failure;

/**
 * Factory to create different AES modes
 */
public final class AESFactory {
    /**
     * Creates an AES instance with GCM context
     * @param context contains GCM specific configuration
     * @return AES GCM instance
     */
    public static AES aesWith(final GCMContext context) {
        notNull(context);

        return new AES() {
            @Override
            public final Result<Throwable, byte[], AESRejectReason> encrypt(final byte[] data) {
                notNull(data);

                try {
                    return new GCM(context.encryption()).encrypt(data);
                } catch (Throwable e) {
                    return failure(new AESFailure(e.getClass()));
                }
            }

            @Override
            public final Result<Throwable, byte[], AESRejectReason> decrypt(final byte[] data) {
                notNull(data);

                try {
                    return new GCM(context.decryption()).decrypt(data);
                } catch (Throwable e) {
                    return failure(new AESFailure(e.getClass()));
                }
            }
        };
    }
}
