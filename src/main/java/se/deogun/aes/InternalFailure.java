package se.deogun.aes;

import static org.apache.commons.lang3.Validate.notNull;

public final class InternalFailure extends RuntimeException {
    public final Class<? extends Exception> origin;

    public InternalFailure(final Class<? extends Exception> origin) {
        this.origin = notNull(origin);
    }
}
