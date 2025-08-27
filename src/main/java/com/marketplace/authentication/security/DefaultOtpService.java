package com.marketplace.authentication.security;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException exception) {
            log.error(exception.getMessage(), exception);
            return null;
        }
    }

    public String generateCurrentCode(String base64Secret) {
        try {
            byte[] decodeSecretKey = Base64.getDecoder().decode(base64Secret);
            SecretKey secretKey = new SecretKeySpec(decodeSecretKey, totpGenerator.getAlgorithm());

            int otp = totpGenerator.generateOneTimePassword(secretKey, Instant.now());

            return String.format("%06d", otp);
        } catch (Exception exception) {
            log.error(exception.getMessage(), exception);
            return null;
        }
    } 

    public boolean verifyCode(String code, String base64Secret) {
        try {
            byte[] decodeSecretKey = Base64.getDecoder().decode(base64Secret);
            SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(decodeSecretKey, totpGenerator.getAlgorithm());
            int otp = Integer.parseInt(code);
            System.out.println(totpGenerator.generateOneTimePassword(secretKey, Instant.now()) + "??????????????");
            return totpGenerator.generateOneTimePassword(secretKey, Instant.now()) == otp;
        } catch (Exception exception) {
            log.error(exception.getMessage(), exception);
            return false;
        }
    }
}
