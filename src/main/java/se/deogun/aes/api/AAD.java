package se.deogun.aes.api;

public final class AAD {
    public final transient String value;

    public AAD(final String value) {
        isValid(value);
        satisfiesUpperBound(value.getBytes().length < 8193); //Just to have an upper bound

        this.value = value;
    }

    private static void isValid(final String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Null or blank not allowed as input");
        }
    }

    private static void satisfiesUpperBound(final boolean invariant) {
        if (!invariant) {
            throw new IllegalArgumentException("Invariant failure for input");
        }
    }
}
