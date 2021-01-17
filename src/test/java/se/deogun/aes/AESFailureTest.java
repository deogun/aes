package se.deogun.aes;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.InternalValidationFailure;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class AESFailureTest {
    @SuppressWarnings("ThrowableNotThrown")
    @Test
    void should_translate_null_internal_failure_to_aes_failure() {
        final InternalValidationFailure nullFailure = null;

        assertThrows(AESFailure.class, () -> new AESFailure(nullFailure));
    }

    @SuppressWarnings("ThrowableNotThrown")
    @Test
    void should_translate_null_throwable_class_to_aes_failure() {
        final Class<Throwable> nullThrowable = null;

        assertThrows(AESFailure.class, () -> new AESFailure(nullThrowable));
    }

    @Test
    void should_accept_throwable_class() {
        assertDoesNotThrow(() -> new AESFailure(IOException.class));
    }

    @Test
    void should_accept_internal_failure() {
        assertDoesNotThrow(() -> new AESFailure(new InternalValidationFailure()));
    }
}