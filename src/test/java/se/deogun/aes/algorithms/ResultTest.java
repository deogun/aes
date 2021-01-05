package se.deogun.aes.algorithms;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static se.deogun.aes.algorithms.AESRejectReason.INVALID_GCM_TAG;

class ResultTest {
    static final RuntimeException EXCEPTION = new RuntimeException();
    static final byte[] DATA = {1, 2, 3};

    interface EventPublisher {
        void fire(Object data);
    }

    final EventPublisher eventPublisher = mock(EventPublisher.class);

    @Test
    void should_give_accepted_result() {
        Result.<RuntimeException, byte[], AESRejectReason>accept(DATA)
                .handle(success -> success
                        .accept(value -> eventPublisher.fire(value))
                        .reject(reason -> eventPublisher.fire(reason)))
                .or(failure -> eventPublisher.fire(failure.getMessage()));

        verify(eventPublisher).fire(DATA);
        verify(eventPublisher, never()).fire(any(AESRejectReason.class));
        verify(eventPublisher, never()).fire(any(String.class));
    }

    @Test
    void should_give_rejected_result() {
        Result.<RuntimeException, byte[], AESRejectReason>reject(INVALID_GCM_TAG)
                .handle(success -> success
                        .accept(value -> eventPublisher.fire(value))
                        .reject(reason -> eventPublisher.fire(reason)))
                .or(failure -> eventPublisher.fire(failure.getMessage()));

        verify(eventPublisher).fire(INVALID_GCM_TAG);
        verify(eventPublisher, never()).fire(any(byte[].class));
        verify(eventPublisher, never()).fire(any(String.class));
    }

    @Test
    void should_give_failed_result() {
        Result.<RuntimeException, byte[], AESRejectReason>failure(EXCEPTION)
                .handle(success -> success
                        .accept(value -> eventPublisher.fire(value))
                        .reject(reason -> eventPublisher.fire(reason.name())))
                .or(failure -> eventPublisher.fire(failure.getMessage()));

        verify(eventPublisher, never()).fire(any(byte[].class));
        verify(eventPublisher, never()).fire(AESRejectReason.class);
        verify(eventPublisher).fire(EXCEPTION.getMessage());
    }

    @Test
    void should_lift_accept() {
        final Result<RuntimeException, byte[], AESRejectReason> result = Result.accept(DATA);

        assertTrue(result.isAccept());
        assertFalse(result.isReject());
        assertFalse(result.isFailure());
        assertTrue(Arrays.equals(DATA, result.liftAccept()));
    }

    @Test
    void should_lift_reject() {
        final Result<RuntimeException, byte[], AESRejectReason> result = Result.reject(INVALID_GCM_TAG);

        assertFalse(result.isAccept());
        assertTrue(result.isReject());
        assertFalse(result.isFailure());
        assertEquals(INVALID_GCM_TAG, result.liftReject());
    }

    @Test
    void should_lift_failure() {
        final Result<RuntimeException, byte[], AESRejectReason> result = Result.failure(EXCEPTION);

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
        final var result = Result.reject(INVALID_GCM_TAG).transform(
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