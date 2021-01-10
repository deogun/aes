package se.deogun.aes;

import se.deogun.aes.modes.Secret;
import se.deogun.aes.modes.gcm.AAD;
import se.deogun.aes.modes.gcm.Context;
import se.deogun.aes.modes.gcm.GCMContext;

import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

/**
 * Factory to create different AES mode contexts
 */
public final class AESContextFactory {

    public static GCMContext gcm(final Secret secret, final AAD aad) {
        notNull(secret);
        notNull(aad);

        //TODO Simplify this...
        return new GCMContext() {
            @Override
            public Context encryption() {
                return new Context(secret, aad);
            }

            @Override
            public Context decryption() {
                return new Context(secret, aad);
            }
        };
    }
}
