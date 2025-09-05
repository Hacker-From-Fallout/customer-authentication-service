package com.marketplace.authentication.security;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CryptoUtils {

    private final String base64SecretKeyAES;

    public String generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }

    public String encrypt(String data) {
        try {
            SecretKey secretKey = getSecretKeyFromBase64(base64SecretKeyAES);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }

    public String decrypt(String encryptedData) {
        try {
            SecretKey secretKey = getSecretKeyFromBase64(base64SecretKeyAES);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }

    private SecretKey getSecretKeyFromBase64(String base64SecretKeyAES) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64SecretKeyAES);
        return new SecretKeySpec(decodedBytes, "AES");
    }
}