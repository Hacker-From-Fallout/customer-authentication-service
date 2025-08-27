package com.marketplace.authentication.security;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class AccessTokenJwsStringDeserializer implements Function<String, Token> {

    private final JWSVerifier jwsVerifier;

    @Override
    public Token apply(String string) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(string);

            if (signedJWT.verify(jwsVerifier)) {
                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

                return new Token(
                    UUID.fromString(jwtClaimsSet.getJWTID()),
                    jwtClaimsSet.getSubject(),
                    jwtClaimsSet.getStringListClaim("authorities"),
                    jwtClaimsSet.getIssueTime().toInstant(),
                    jwtClaimsSet.getExpirationTime().toInstant());
            }

        } catch(ParseException | JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }

        return null;
    }
}
