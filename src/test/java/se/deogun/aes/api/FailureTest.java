package se.deogun.aes.api;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FailureTest {

    @SuppressWarnings("ThrowableNotThrown")
    @Test
    void should_translate_null_throwable_class_to_failure() {
        assertThrows(Failure.class, () -> new Failure(null));
    }

    @SuppressWarnings("ThrowableNotThrown")
    @Test
    void should_have_NPE_as_origin() {
        try {
            new Failure(null);
        } catch (Failure e) {
            assertEquals(NullPointerException.class, e.origin);
            return;
        }
        fail("catch clause not executed");
    }

    @Test
    void should_accept_throwable_class() {
        assertDoesNotThrow(() -> new Failure(Throwable.class));
    }
}