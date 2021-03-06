package se.deogun.aes.api;

public final class Failure extends RuntimeException {
    public final Class<? extends Throwable> origin;

    public Failure(final Class<? extends Throwable> origin) {
        this.origin = notNull(origin);
    }

    private static <T> T notNull(T input) {
        if (input == null) {
            throw new Failure(NullPointerException.class);
        }
        return input;
    }
}
