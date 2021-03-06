package se.deogun.aes.modes.common;

import org.junit.jupiter.api.Test;
import se.deogun.aes.modes.common.InternalRejectReason;
import se.deogun.aes.modes.common.Result;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static se.deogun.aes.modes.common.InternalRejectReason.GCM_INVALID_TAG;

class ResultTest {
    static final RuntimeException EXCEPTION = new RuntimeException();
    static final byte[] DATA = {1, 2, 3};

    interface EventPublisher {
        void fire(Object data);
    }

    final EventPublisher eventPublisher = mock(EventPublisher.class);

    @Test
    void should_give_accepted_result() {
        Result.<RuntimeException, byte[], InternalRejectReason>accept(DATA)
                .handle(success -> success
                        .accept(value -> assertTrue(Arrays.equals(DATA, value)))
                        .reject(reason -> fail("unexpected reject: " + reason)))
                .or(failure -> fail("unexpected failure: " + failure.getMessage()));
    }

    @Test
    void should_give_rejected_result() {
        Result.<RuntimeException, byte[], InternalRejectReason>reject(GCM_INVALID_TAG)
                .handle(success -> success
                        .accept(value -> fail("unexpected accept: " + Arrays.toString(value)))
                        .reject(reason -> assertEquals(GCM_INVALID_TAG, reason)))
                .or(failure -> fail("unexpected failure: " + failure.getMessage()));
    }

    @Test
    void should_give_failed_result() {
        Result.<RuntimeException, byte[], InternalRejectReason>failure(EXCEPTION)
                .handle(success -> success
                        .accept(value -> fail("unexpected accept: " + Arrays.toString(value)))
                        .reject(reason -> fail("unexpected reject: " + reason)))
                .or(failure -> assertEquals(EXCEPTION, failure));
    }

    @Test
    void should_lift_accept() {
        final Result<RuntimeException, byte[], InternalRejectReason> result = Result.accept(DATA);

        assertTrue(result.isAccept());
        assertFalse(result.isReject());
        assertFalse(result.isFailure());
        assertTrue(Arrays.equals(DATA, result.liftAccept()));
    }

    @Test
    void should_lift_reject() {
        final Result<RuntimeException, byte[], InternalRejectReason> result = Result.reject(GCM_INVALID_TAG);

        assertFalse(result.isAccept());
        assertTrue(result.isReject());
        assertFalse(result.isFailure());
        assertEquals(GCM_INVALID_TAG, result.liftReject());
    }

    @Test
    void should_lift_failure() {
        final Result<RuntimeException, byte[], InternalRejectReason> result = Result.failure(EXCEPTION);

        assertFalse(result.isAccept());
        assertFalse(result.isReject());
        assertTrue(result.isFailure());
        assertEquals(EXCEPTION, result.liftFailure());
    }

    @Test
    void should_transform_accept() {
        final var result = Result.accept(DATA).transform(
                accept -> Result.<Throwable, String, Integer>accept("accept"),
                reject -> Result.<Throwable, String, Integer>reject(42),
                failure -> Result.<Throwable, String, Integer>failure(new SecurityException())
        );

        assertEquals("accept", result.liftAccept());
    }

    @Test
    void should_transform_reject() {
        final var result = Result.reject(GCM_INVALID_TAG).transform(
                accept -> Result.<Throwable, String, Integer>accept("accept"),
                reject -> Result.<Throwable, String, Integer>reject(42),
                failure -> Result.<Throwable, String, Integer>failure(new SecurityException())
        );

        assertEquals(42, result.liftReject());
    }

    @Test
    void should_transform_failure() {
        final var result = Result.failure(new IOException()).transform(
                accept -> Result.<Throwable, String, Integer>accept("accept"),
                reject -> Result.<Throwable, String, Integer>reject(42),
                failure -> Result.<Throwable, String, Integer>failure(EXCEPTION)
        );

        assertEquals(EXCEPTION, result.liftFailure());
    }
}