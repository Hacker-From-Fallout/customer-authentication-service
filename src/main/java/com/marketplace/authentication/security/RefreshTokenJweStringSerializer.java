package com.marketplace.authentication.security;

import java.util.Date;
import java.util.function.Function;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class RefreshTokenJweStringSerializer implements Function<Token, String> {

    private final JWEEncrypter jweEncrypter;
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    @Override
    public String apply(Token token) {

        JWEHeader jweHeader = new JWEHeader.Builder(jweAlgorithm, encryptionMethod)
            .keyID(token.id().toString())
            .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
            .jwtID(token.id().toString())
            .subject(token.subject())
            .issueTime(Date.from(token.createdAt()))
            .expirationTime(Date.from(token.expiresAt()))
            .claim("authorities", token.authorities())
            .build();
        
        EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader, jwtClaimsSet);

        try {
            encryptedJWT.encrypt(jweEncrypter);

            return encryptedJWT.serialize();
        } catch(JOSEException exception) {
            log.error(exception.getMessage(), exception);

            return null;
        }
    }

    public void setJweEncrypter(JWEAlgorithm jweAlgorithm) {
        this.jweAlgorithm = jweAlgorithm;
    }

    public void setEncryptionMethod(EncryptionMethod encryptionMethod) {
        this.encryptionMethod = encryptionMethod;
    }
}
