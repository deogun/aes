package se.deogun.aes;

import se.deogun.aes.modes.AESRejectReason;
import se.deogun.aes.modes.Result;
import se.deogun.aes.modes.Secret;
import se.deogun.aes.modes.gcm.AAD;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static se.deogun.aes.AESFactory.aesGCM;

public class Main {
    public static void main(String[] args) {
        final var aes = aesGCM(new Secret(serialize(secretKey())), new AAD(randomAlphanumeric(8192)));

        final Result<? extends Throwable, byte[], AESRejectReason> encryptResult1 = aes.encrypt("some message 12345".getBytes());
        encryptResult1
                .handle(success -> success
                        .accept(value -> System.out.println("successful encryption: " + Base64.getEncoder().encodeToString(value)))
                        .reject(reason -> System.out.println("rejected encryption: " + reason)))
                .or(failure -> failure.printStackTrace());

        final Result<? extends Throwable, byte[], AESRejectReason> encryptResult2 = aes.encrypt("foo bar".getBytes());
        encryptResult2
                .handle(success -> success
                        .accept(value -> System.out.println("successful encryption: " + Base64.getEncoder().encodeToString(value)))
                        .reject(reason -> System.out.println("rejected encryption: " + reason)))
                .or(failure -> failure.printStackTrace());

        aes.decrypt(encryptResult1.liftAccept())
                .handle(success -> success
                        .accept(value -> System.out.println("successful decryption: " + new String(value)))
                        .reject(reason -> System.out.println("rejected decryption: " + reason)))
                .or(failure -> failure.printStackTrace());

        aes.decrypt(encryptResult2.liftAccept())
                .handle(success -> success
                        .accept(value -> System.out.println("successful decryption: " + new String(value)))
                        .reject(reason -> System.out.println("rejected decryption: " + reason)))
                .or(failure -> failure.printStackTrace());
    }

    private static byte[] serialize(final SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded()).getBytes();
    }

    private static SecretKey secretKey() {
        try {
            final var instance = KeyGenerator.getInstance("AES");
            instance.init(256, SecureRandom.getInstanceStrong());
            return instance.generateKey();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
