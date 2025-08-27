package com.marketplace.authentication.security;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class RefreshTokenJweStringDeserializer implements Function<String, Token> {

    private final JWEDecrypter jweDecrypter;

    @Override
    public Token apply(String string) {
        try {
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(string);
            encryptedJWT.decrypt(jweDecrypter);
            JWTClaimsSet jwtClaimsSet = encryptedJWT.getJWTClaimsSet();

            return new Token(
                UUID.fromString(jwtClaimsSet.getJWTID()),
                jwtClaimsSet.getSubject(),
                jwtClaimsSet.getStringListClaim("authorities"),
                jwtClaimsSet.getIssueTime().toInstant(),
                jwtClaimsSet.getExpirationTime().toInstant()
            );
        } catch(ParseException | JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }

        return null;
    }
}
