package com.marketplace.authentication.security;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultOtpService implements OtpService {

    private final TimeBasedOneTimePasswordGenerator totpGenerator;

    public String generateSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(totpGenerator.getAlgorithm());
            keyGenerator.init(160);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] encoded = secretKey.getEncoded();
            Base32 base32 = new Base32();
            String base32Secret = base32.encodeAsString(encoded);

            return base32Secret;
        } catch (NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }

    public String generateCurrentCode(String base32Secret) {
        try {
            Base32 base32 = new Base32();
            byte[] decodedBytes = base32.decode(base32Secret);
            SecretKey secretKey = new SecretKeySpec(decodedBytes, totpGenerator.getAlgorithm());
            int otp = totpGenerator.generateOneTimePassword(secretKey, Instant.now());

            return String.format("%06d", otp);
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }

    public boolean verifyCode(String code, String base32Secret) {
        try {
            Base32 base32 = new Base32();
            byte[] decodedBytes = base32.decode(base32Secret);
            SecretKey secretKey = new SecretKeySpec(decodedBytes, totpGenerator.getAlgorithm());
            int otp = Integer.parseInt(code);
            int generatedOtp = totpGenerator.generateOneTimePassword(secretKey, Instant.now());
        
            return generatedOtp == otp;
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }
}
