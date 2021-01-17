package se.deogun.aes;

import se.deogun.aes.modes.InternalValidationFailure;

public final class AESFailure extends RuntimeException {
    public final Class<? extends Throwable> origin;

    public AESFailure(final Class<? extends Throwable> origin) {
        this.origin = notNull(origin);
    }

    public AESFailure(final InternalValidationFailure origin) {
        super(notNull(origin));
        this.origin = notNull(origin.getClass());
    }

    private static <T> T notNull(T input) {
        if (input == null) {
            throw new AESFailure(new InternalValidationFailure());
        }
        return input;
    }
}
