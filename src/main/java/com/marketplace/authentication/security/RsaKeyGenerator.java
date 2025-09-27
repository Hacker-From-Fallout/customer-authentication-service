package com.marketplace.authentication.security;

import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class RsaKeyGenerator {
    
    public static void main(String[] args) {
        try {
            generateKeys(2048, "private_key.pem", "public_key.pem");
            System.out.println("Ключи успешно сгенерированы");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void generateKeys(int keySize, String privateKeyPath, String publicKeyPath) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        saveKeyToPem(privateKey, privateKeyPath);
        saveKeyToPem(publicKey, publicKeyPath);
    }

    private static void saveKeyToPem(Key key, String filepath) throws IOException {
        try (PemWriter pemWriter = new PemWriter(new FileWriter(filepath))) {
            String type;
            if (key instanceof PrivateKey) {
                type = "PRIVATE KEY";
            } else if (key instanceof PublicKey) {
                type = "PUBLIC KEY";
            } else {
                throw new IllegalArgumentException("Некорректный тип ключа");
            }
            PemObject pemObject = new PemObject(type, key.getEncoded());
            pemWriter.writeObject(pemObject);
        }
    }
}
