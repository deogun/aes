package se.deogun.aes.modes;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.common.InternalValidationFailure;

import static org.junit.jupiter.api.Assertions.*;

class InternalValidationTest {
    @Test
    void should_accept_non_null_input() {
        assertDoesNotThrow(() -> InternalValidation.isNotNull(new Object()));
    }

    @Test
    void should_reject_null_input() {
        assertThrows(InternalValidationFailure.class, () -> InternalValidation.isNotNull(null));
    }

    @Test
    void should_have_inclusive_lower_bound() {
        assertTrue(InternalValidation.isInRange(1, 1, 100));
    }

    @Test
    void should_have_inclusive_upper_bound() {
        assertTrue(InternalValidation.isInRange(100, 1, 100));
    }

    @Test
    void should_be_rejected_when_less_than_lower_bound() {
        assertFalse(InternalValidation.isInRange(0, 1, 100));
    }

    @Test
    void should_be_rejected_when_greater_than_upper_bound() {
        assertFalse(InternalValidation.isInRange(101, 1, 100));
    }

    @Test
    void should_be_accepted() {
        assertDoesNotThrow(() -> InternalValidation.isTrue(true));
    }

    @Test
    void should_be_rejected() {
        assertThrows(InternalValidationFailure.class, () -> InternalValidation.isTrue(false));
    }
}