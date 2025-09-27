package com.marketplace.authentication.security;

import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.jwk.RSAKey;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwkGeneratorService {
    
    private final String keyId;
    private final String publicKeyPath;

    public JwkGeneratorService(String keyId, String publicKeyPath) {
        this.keyId = keyId;
        this.publicKeyPath = publicKeyPath;
    }

    public String getPublicKeyJwkResponse() {
        try {
            RSAPublicKey publicKey = RsaKeyLoader.loadPublicKey(publicKeyPath);
            String jwkJson = generatePublicJwkJson(publicKey);
            return jwkJson;
        } catch (Exception exception) {
            log.error(exception.getMessage(), exception);
            return null;
        }
    }

    private String generatePublicJwkJson(RSAPublicKey publicKey) {
        RSAKey jwk = new RSAKey.Builder(publicKey)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .keyID(keyId)
                .build();

        return jwk.toPublicJWK().toJSONString();
    }
}
