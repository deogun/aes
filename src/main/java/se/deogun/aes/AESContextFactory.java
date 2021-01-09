package se.deogun.aes;

import se.deogun.aes.algorithms.AESContext;
import se.deogun.aes.algorithms.InitVector;
import se.deogun.aes.algorithms.Secret;
import se.deogun.aes.algorithms.gcm.AAD;
import se.deogun.aes.algorithms.gcm.GCMContext;

import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

public final class AESContextFactory {
    public static AESContext<GCMContext> gcm(final Secret secret, final InitVector initVector, final AAD aad) {
        notNull(secret);
        notNull(initVector);
        notNull(aad);

        return gcm(secret, initVector, aad, 1, 1);
    }

    public static AESContext<GCMContext> gcm(final Secret secret, final InitVector initVector, final AAD aad,
                                             final int maxNoEncryptions, final int maxNoDecryptions) {
        notNull(secret);
        notNull(initVector);
        notNull(aad);
        isTrue(maxNoEncryptions > -1);
        isTrue(maxNoDecryptions > -1);

        final var encryptionContext = new GCMContext(initVector, secret, aad, new AtomicInteger(maxNoEncryptions));
        final var decryptionContext = new GCMContext(initVector, secret, aad, new AtomicInteger(maxNoDecryptions));

        return new AESContext<>() {
            @Override
            public GCMContext encryption() {
                return encryptionContext;
            }

            @Override
            public GCMContext decryption() {
                return decryptionContext;
            }
        };
    }
}
