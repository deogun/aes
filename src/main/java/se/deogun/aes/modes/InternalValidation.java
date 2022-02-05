package se.deogun.aes.modes;

import se.deogun.aes.modes.common.InternalValidationFailure;

final class InternalValidation {
    static void isNotNull(final Object input) {
        if (input == null) {
            throw new InternalValidationFailure();
        }
    }

    static boolean isInRange(final int value, final int start, final int end) {
        return value >= start && value <= end;
    }

    public static void isTrue(final boolean value) {
        if(!value) {
            throw new InternalValidationFailure();
        }
    }
}
