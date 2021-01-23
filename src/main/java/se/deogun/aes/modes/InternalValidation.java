package se.deogun.aes.modes;

final class InternalValidation {
    static void isNotNull(final Object input) {
        if (input == null) {
            throw new InternalValidationFailure();
        }
    }

    static void satisfiesInvariant(final boolean invariant) {
        if (!invariant) {
            throw new InternalValidationFailure();
        }
    }
}
