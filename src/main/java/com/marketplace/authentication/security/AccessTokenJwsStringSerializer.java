package com.marketplace.authentication.security;

import java.util.Date;
import java.util.function.Function;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class AccessTokenJwsStringSerializer implements Function<Token, String> {

    private final JWSSigner jwsSigner;
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    @Override
    public String apply(Token token) {

        JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlgorithm)
            .keyID(token.id().toString())
            .build();
        
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
            .jwtID(token.id().toString())
            .subject(token.subject())
            .issueTime(Date.from(token.createdAt()))
            .expirationTime(Date.from(token.expiresAt()))
            .claim("authorities", token.authorities())
            .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        try {
            signedJWT.sign(jwsSigner);

            return signedJWT.serialize();
        } catch (JOSEException exception) {
            log.error(exception.getMessage(), exception);

            return null;
        }
    }

    public void setJwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
        this.jwsAlgorithm = jwsAlgorithm;
    }
}
