package se.deogun.aes;

import se.deogun.aes.api.*;
import se.deogun.aes.modes.AADMode;
import se.deogun.aes.modes.NonAADMode;
import se.deogun.aes.modes.common.InternalRejectReason;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Supplier;

import static java.lang.String.format;
import static se.deogun.aes.api.DecryptBufferSize._16KB_DECRYPT_BUFFER_SIZE;
import static se.deogun.aes.api.RejectReason.ALGORITHM_NOT_SUPPORTING_AAD;
import static se.deogun.aes.api.Result.reject;
import static se.deogun.aes.modes.ModeFactory.cbc;
import static se.deogun.aes.modes.ModeFactory.gcm;
import static se.deogun.aes.modes.common.AAD.NO_AAD;

/**
 * Factory to create different AES modes
 */
public final class AESFactory {
    /**
     * Creates an AES instance with GCM mode and 16KB decrypt buffer size
     *
     * @param secret secret to be used for encryption / decryption
     * @return AES service
     */
    public static AES aesGCM(final Secret secret) {
        return aesGCM(secret, _16KB_DECRYPT_BUFFER_SIZE);
    }

    /**
     * Creates an AES instance with GCM mode
     *
     * @param secret secret to be used for encryption / decryption
     * @return AES service
     */
    public static AES aesGCM(final Secret secret, final DecryptBufferSize decryptBufferSize) {
        notNull(secret, "Secret");
        notNull(decryptBufferSize, "Decrypt buffer size");
        return gcm(mode -> aesSupportingAAD(secret, mode), decryptBufferSize.size);
    }


    /**
     * Creates an AES instance with CBC mode and 16KB decrypt buffer size
     *
     * @param secret secret to be used for encryption / decryption
     * @return AES service
     */
    public static AES aesCBC(final Secret secret) {
        return aesCBC(secret, _16KB_DECRYPT_BUFFER_SIZE);
    }

    /**
     * Creates an AES instance with CBC mode and 16KB decrypt buffer size
     *
     * @param secret secret to be used for encryption / decryption
     * @return AES service
     */
    public static AES aesCBC(final Secret secret, final DecryptBufferSize decryptBufferSize) {
        notNull(secret, "Secret");
        notNull(decryptBufferSize, "Decrypt buffer size");
        return cbc(mode -> aesNotSupportingAAD(secret, mode), decryptBufferSize.size);
    }

    private static AES aesNotSupportingAAD(final Secret secret, final NonAADMode mode) {
        return new AES() {
            @Override
            public Result<? super Failure, byte[], RejectReason> encrypt(final byte[] data) {
                notNull(data, "Encryption data");
                return apply(() -> mode.encrypt(data, secret(secret)));
            }

            @Override
            public Result<? super Failure, OutputStream, RejectReason> encrypt(final byte[] data, final OutputStream outputStream) {
                notNull(data, "Encryption data");
                notNull(outputStream, "OutputStream");
                return apply(() -> mode.encrypt(data, outputStream, secret(secret)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final byte[] data) {
                notNull(data, "Encryption data");
                return apply(() -> mode.decrypt(data, secret(secret)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final InputStream inputStream) {
                notNull(inputStream, "Decryption data");
                return apply(() -> mode.decrypt(inputStream, secret(secret)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> encrypt(final byte[] data, final AAD aad) {
                return reject(ALGORITHM_NOT_SUPPORTING_AAD);
            }

            @Override
            public Result<? super Failure, OutputStream, RejectReason> encrypt(final byte[] data, final OutputStream outputStream, final AAD aad) {
                return reject(ALGORITHM_NOT_SUPPORTING_AAD);
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final byte[] data, final AAD aad) {
                return reject(ALGORITHM_NOT_SUPPORTING_AAD);
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final InputStream inputStream, final AAD aad) {
                return reject(ALGORITHM_NOT_SUPPORTING_AAD);
            }

            private se.deogun.aes.modes.common.Secret secret(final Secret secret) {
                return new se.deogun.aes.modes.common.Secret(secret.key());
            }
        };
    }

    private static AES aesSupportingAAD(final Secret secret, final AADMode mode) {
        return new AES() {
            @Override
            public Result<? super Failure, byte[], RejectReason> encrypt(final byte[] data, final AAD aad) {
                notNull(data, "Encryption data");
                notNull(aad, "AAD");
                return apply(() -> mode.encrypt(data, secret(secret), aad(aad)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> encrypt(final byte[] data) {
                notNull(data, "Encryption data");
                return apply(() -> mode.encrypt(data, secret(secret), NO_AAD));
            }

            @Override
            public Result<? super Failure, OutputStream, RejectReason> encrypt(final byte[] data, final OutputStream outputStream, final AAD aad) {
                notNull(data, "Encryption data");
                notNull(outputStream, "OutputStream");
                notNull(aad, "AAD");
                return apply(() -> mode.encrypt(data, outputStream, secret(secret), aad(aad)));
            }

            @Override
            public Result<? super Failure, OutputStream, RejectReason> encrypt(final byte[] data, final OutputStream outputStream) {
                notNull(data, "Encryption data");
                notNull(outputStream, "OutputStream");
                return apply(() -> mode.encrypt(data, outputStream, secret(secret), NO_AAD));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final byte[] data, final AAD aad) {
                notNull(data, "Encryption data");
                notNull(aad, "AAD");
                return apply(() -> mode.decrypt(data, secret(secret), aad(aad)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final byte[] data) {
                notNull(data, "Encryption data");
                return apply(() -> mode.decrypt(data, secret(secret), NO_AAD));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final InputStream inputStream, final AAD aad) {
                notNull(inputStream, "InputStream");
                notNull(aad, "AAD");
                return apply(() -> mode.decrypt(inputStream, secret(secret), aad(aad)));
            }

            @Override
            public Result<? super Failure, byte[], RejectReason> decrypt(final InputStream inputStream) {
                notNull(inputStream, "InputStream");
                return apply(() -> mode.decrypt(inputStream, secret(secret), NO_AAD));
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
                            reject -> reject(reject.toAPI()),
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
