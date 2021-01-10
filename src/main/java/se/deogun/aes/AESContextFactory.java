package se.deogun.aes;

import se.deogun.aes.modes.InitVector;
import se.deogun.aes.modes.Secret;
import se.deogun.aes.modes.gcm.AAD;
import se.deogun.aes.modes.gcm.Context;
import se.deogun.aes.modes.gcm.GCMContext;

import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

public final class AESContextFactory {
    public static GCMContext gcm(final Secret secret, final InitVector initVector, final AAD aad) {
        notNull(secret);
        notNull(initVector);
        notNull(aad);

        return gcm(secret, initVector, aad, 1, 1);
    }

    public static GCMContext gcm(final Secret secret, final InitVector initVector, final AAD aad,
                                 final int maxNoEncryptions, final int maxNoDecryptions) {
        notNull(secret);
        notNull(initVector);
        notNull(aad);
        isTrue(maxNoEncryptions > -1);
        isTrue(maxNoDecryptions > -1);

        final var encryptionContext = new Context(initVector, secret, aad, new AtomicInteger(maxNoEncryptions));
        final var decryptionContext = new Context(initVector, secret, aad, new AtomicInteger(maxNoDecryptions));

        return new GCMContext() {
            @Override
            public Context encryption() {
                return encryptionContext;
            }

            @Override
            public Context decryption() {
                return decryptionContext;
            }
        };
    }
}
