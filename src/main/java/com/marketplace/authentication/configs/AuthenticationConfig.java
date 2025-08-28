package com.marketplace.authentication.configs;

import java.util.function.Function;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.marketplace.authentication.security.AccessTokenJwsStringSerializer;
import com.marketplace.authentication.security.RefreshTokenJweStringSerializer;
import com.marketplace.authentication.security.Token;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;

@Configuration
public class AuthenticationConfig {

    @Value("${jwt.access-token-key}") 
    private String accessTokenKey;

    @Value("${jwt.refresh-token-key}") 
    private String refreshTokenKey;

    @Bean
    @Qualifier("accessTokenStringSerializer")
    public Function<Token, String> accessTokenStringSerializer() {
        try {
            return new AccessTokenJwsStringSerializer(
                new MACSigner(OctetSequenceKey.parse(accessTokenKey))
            );
        } catch (Exception exception) {
            throw new RuntimeException("Ошибка при создании сериализатора accessToken", exception);
        }
    }

    @Bean
    @Qualifier("refreshTokenStringSerializer")
    public Function<Token, String> refreshTokenStringSerializer() {
        try {
            return new RefreshTokenJweStringSerializer(
                new DirectEncrypter(OctetSequenceKey.parse(refreshTokenKey))
            );
        } catch (Exception exception) {
            throw new RuntimeException("Ошибка при создании сериализатора refreshToken", exception);
        }
    }
}
