package com.marketplace.authentication.security;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    public static String generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static String encrypt(String data, String base64SecretKey) throws Exception {
        SecretKey secretKey = getSecretKeyFromBase64(base64SecretKey);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedData, String base64SecretKey) throws Exception {
        SecretKey secretKey = getSecretKeyFromBase64(base64SecretKey);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }

    private static SecretKey getSecretKeyFromBase64(String base64SecretKey) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64SecretKey);
        return new SecretKeySpec(decodedBytes, "AES");
    }
}
