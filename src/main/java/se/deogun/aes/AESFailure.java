package se.deogun.aes;

import static org.apache.commons.lang3.Validate.notNull;

public final class AESFailure extends RuntimeException {
    public final Class<? extends Throwable> origin;

    public AESFailure(final Class<? extends Throwable> origin) {
        this.origin = notNull(origin);
    }
}
