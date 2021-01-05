package se.deogun.aes.algorithms;

import java.security.GeneralSecurityException;

import static org.apache.commons.lang3.Validate.notNull;

public class InternalCryptoFailure extends RuntimeException {
    public final Class<? extends GeneralSecurityException> origin;

    public InternalCryptoFailure(final Class<? extends GeneralSecurityException> origin) {
        this.origin = notNull(origin);
    }
}
