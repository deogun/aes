package se.deogun.aes.api;


import se.deogun.aes.modes.common.InternalValidationFailure;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import static java.util.Optional.ofNullable;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public final class Result<FAILURE_TYPE extends Throwable, ACCEPT_TYPE, REJECT_TYPE> {
    private final Optional<Success<ACCEPT_TYPE, REJECT_TYPE>> success;
    private final Optional<Failure<FAILURE_TYPE>> failure;

    private Result(final Success<ACCEPT_TYPE, REJECT_TYPE> success) {
        this(success, null);
    }

    private Result(final Failure<FAILURE_TYPE> failure) {
        this(null, failure);
    }

    private Result(final Success<ACCEPT_TYPE, REJECT_TYPE> success, final Failure<FAILURE_TYPE> failure) {
        this.failure = ofNullable(failure);
        this.success = ofNullable(success);

        ensure(this.success.isEmpty() && this.failure.isPresent() ||
                this.success.isPresent() && this.failure.isEmpty());
    }

    public static <F extends Throwable, A, R> Result<F, A, R> failure(final F exception) {
        return new Result<>(new Failure<>(exception));
    }

    public static <F extends Throwable, A, R> Result<F, A, R> accept(final A data) {
        return new Result<>(new Success<>(new Accept<>(data)));
    }

    public static <F extends Throwable, A, R> Result<F, A, R> reject(final R data) {
        return new Result<>(new Success<>(new Reject<>(data)));
    }

    private Throwable failure() {
        return failure
                .map(value -> value.exception)
                .orElseThrow(() -> new UnsupportedOperationException());
    }

    private Success<ACCEPT_TYPE, REJECT_TYPE> success() {
        return success.orElseThrow(() -> new UnsupportedOperationException());
    }

    public Result<? extends Throwable, ACCEPT_TYPE, REJECT_TYPE> handle(final Consumer<Success<ACCEPT_TYPE, REJECT_TYPE>> consumer) {
        if (success.isPresent()) {
            consumer.accept(success());
        }
        return this;
    }

    public void or(final Consumer<Throwable> function) {
        if (failure.isPresent()) {
            function.accept(failure());
        }
    }

    public boolean isAccept() {
        return success
                .map(value -> value.accept.isPresent())
                .orElse(false);
    }

    public boolean isReject() {
        return success
                .map(value -> value.reject.isPresent())
                .orElse(false);
    }

    public boolean isFailure() {
        return failure.isPresent();
    }

    public ACCEPT_TYPE liftAccept() {
        return success
                .map(value -> value.accept
                        .map(v -> v.data)
                        .orElseThrow())
                .orElseThrow();
    }

    public REJECT_TYPE liftReject() {
        return success
                .map(value -> value.reject
                        .map(v -> v.data)
                        .orElseThrow())
                .orElseThrow();
    }

    public FAILURE_TYPE liftFailure() {
        return failure
                .map(value -> value.exception)
                .orElseThrow();
    }

    public <T> T transform(final Function<ACCEPT_TYPE, T> acceptTransformation,
                           final Function<REJECT_TYPE, T> rejectTransformation,
                           final Function<FAILURE_TYPE, T> failureTransformation) {
        notNull(acceptTransformation);
        notNull(rejectTransformation);
        notNull(failureTransformation);

        return success
                .map(value -> value.accept
                        .map(v -> acceptTransformation.apply(v.data))
                        .orElseGet(() -> value.reject
                                .map(v -> rejectTransformation.apply(v.data))
                                .orElseThrow()))
                .orElseGet(() -> failure
                        .map(throwable -> failureTransformation.apply(throwable.exception))
                        .orElseThrow());
    }

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    public static class Success<A, R> {
        private final Optional<Accept<A>> accept;
        private final Optional<Reject<R>> reject;

        private Success(final Accept<A> accept) {
            this(accept, null);
        }

        private Success(final Reject<R> reject) {
            this(null, reject);
        }

        private Success(final Accept<A> accept, final Reject<R> reject) {
            this.accept = ofNullable(accept);
            this.reject = ofNullable(reject);
        }

        A accept() {
            return accept
                    .map(value -> value.data)
                    .orElseThrow(() -> new UnsupportedOperationException());
        }

        R reject() {
            return reject
                    .map(value -> value.data)
                    .orElseThrow(() -> new UnsupportedOperationException());
        }

        public Success<A, R> accept(final Consumer<A> consumer) {
            if (accept.isPresent()) {
                consumer.accept(accept());
            }
            return this;
        }

        public void reject(final Consumer<R> consumer) {
            if (accept.isEmpty()) {
                consumer.accept(reject());
            }
        }
    }

    public static final class Accept<T> {
        public final T data;

        public Accept(final T data) {
            this.data = data;
        }
    }

    public static final class Reject<T> {
        public final T data;

        public Reject(final T data) {
            this.data = data;
        }
    }

    public static final class Failure<F extends Throwable> {
        public final F exception;

        Failure(final F exception) {
            this.exception = exception;
        }
    }

    private static void notNull(final Object input) {
        if (input == null) {
            throw new IllegalArgumentException("Null not allowed as input");
        }
    }

    static void ensure(final boolean invariant) {
        if (!invariant) {
            throw new se.deogun.aes.api.Failure(InternalValidationFailure.class);
        }
    }
}
