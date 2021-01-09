package se.deogun.aes;

import se.deogun.aes.algorithms.AES;
import se.deogun.aes.algorithms.AESContext;
import se.deogun.aes.algorithms.AESRejectReason;
import se.deogun.aes.algorithms.Result;
import se.deogun.aes.algorithms.gcm.GCM;
import se.deogun.aes.algorithms.gcm.GCMContext;

import static org.apache.commons.lang3.Validate.notNull;
import static se.deogun.aes.algorithms.Result.failure;

public final class AESFactory {
    public static AES aes(final AESContext<GCMContext> context) {
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
