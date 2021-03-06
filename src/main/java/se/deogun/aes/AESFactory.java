package se.deogun.aes;

import se.deogun.aes.api.*;
import se.deogun.aes.modes.common.InternalRejectReason;
import se.deogun.aes.modes.Mode;
import se.deogun.aes.modes.ModeFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Supplier;

import static java.lang.String.format;

/**
 * Factory to create different AES modes
 */
public final class AESFactory {
    /**
     * Creates an AES instance with GCM mode
     *
     * @param secret secret to be used for encryption / decryption
     * @return AES GCM service
     */
    public static AES aesGCM(final Secret secret) {
        notNull(secret, "Secret");
        return ModeFactory.gcm(mode -> aes(secret, mode));
    }

    private static AES aes(final Secret secret, final Mode mode) {
        return new AES() {
            @Override
            public Result<? super Failure, byte[], RejectReason> encrypt(final byte[] data, final AAD aad) {
                notNull(data, "Encryption data");
                notNull(aad, "AAD");

                return apply(() -> mode.encrypt(data, secret(secret), aad(aad)));
            }

            @Override
            public Result<? super Failure, OutputStream, RejectReason> encrypt(final byte[] data, final OutputStream outputStream, final AAD aad) {
                notNull(data, "Encryption data");
                notNull(outputStream, "OutputStream");
                notNull(aad, "AAD");

                return apply(() -> mode.encrypt(data, outputStream, secret(secret), aad(aad)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final byte[] data, final AAD aad) {
                notNull(data, "Encryption data");
                notNull(aad, "AAD");

                return apply(() -> mode.decrypt(data, secret(secret), aad(aad)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final InputStream inputStream, final AAD aad) {
                notNull(inputStream, "InputStream");
                notNull(aad, "AAD");

                return apply(() -> mode.decrypt(inputStream, secret(secret), aad(aad)));
            }

            private se.deogun.aes.modes.common.AAD aad(final AAD aad) {
                return new se.deogun.aes.modes.common.AAD(aad.value);
            }

            private se.deogun.aes.modes.common.Secret secret(final Secret secret) {
                return new se.deogun.aes.modes.common.Secret(secret.key());
            }
        };
    }

    private static <T> Result<? super Failure, T, RejectReason> apply(final Supplier<se.deogun.aes.modes.common.Result<Throwable, T, InternalRejectReason>> operation) {
        try {
            return operation.get()
                    .transform(
                            accept -> Result.accept(accept),
                            reject -> Result.reject(reject.toAPI()),
                            failure -> Result.failure(failure)
                    );
        } catch (Throwable e) {
            return Result.failure(new Failure(e.getClass()));
        }
    }

    private static void notNull(final Object input, final String identifier) {
        if (input == null) {
            throw new IllegalArgumentException(format("%s cannot be null", identifier));
        }
    }
}
