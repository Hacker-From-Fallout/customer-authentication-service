package com.marketplace.authentication.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class RsaKeyLoader {

    public static RSAPrivateKey loadPrivateKey(String resourcePath) throws IOException {
        try (InputStream is = RsaKeyLoader.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) throw new IOException("Resource not found: " + resourcePath);

            try (PEMParser pemParser = new PEMParser(new InputStreamReader(is))) {
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

                if (object instanceof PrivateKeyInfo) {
                    PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
                    if (!(privateKey instanceof RSAPrivateKey)) {
                        throw new IllegalArgumentException("Не RSA приватный ключ");
                    }
                    return (RSAPrivateKey) privateKey;
                } else {
                    throw new IllegalArgumentException("Файл не содержит приватный ключ");
                }
            }
        }
    }

    public static RSAPublicKey loadPublicKey(String resourcePath) throws IOException {
        try (InputStream is = RsaKeyLoader.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) throw new IOException("Resource not found: " + resourcePath);

            try (PEMParser pemParser = new PEMParser(new InputStreamReader(is))) {
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

                if (object instanceof SubjectPublicKeyInfo) {
                    PublicKey publicKey = converter.getPublicKey((SubjectPublicKeyInfo) object);
                    if (!(publicKey instanceof RSAPublicKey)) {
                        throw new IllegalArgumentException("Не RSA публичный ключ");
                    }
                    return (RSAPublicKey) publicKey;
                } else {
                    throw new IllegalArgumentException("Файл не содержит публичный ключ в ожидаемом формате");
                }
            }
        }
    }
}
