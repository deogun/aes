package se.deogun.aes.modes;

import se.deogun.aes.modes.common.InternalValidationFailure;

final class InternalValidation {
    static void isNotNull(final Object input) {
        if (input == null) {
            throw new InternalValidationFailure();
        }
    }
}
