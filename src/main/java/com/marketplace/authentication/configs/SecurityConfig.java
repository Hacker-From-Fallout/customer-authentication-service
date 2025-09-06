package com.marketplace.authentication.configs;

import java.time.Duration;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.marketplace.authentication.security.AccessTokenJwsStringDeserializer;
import com.marketplace.authentication.security.AccessTokenJwsStringSerializer;
import com.marketplace.authentication.security.BlacklistTokenService;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.DefaultAccessTokenFactory;
import com.marketplace.authentication.security.DefaultRefreshTokenFactory;
import com.marketplace.authentication.security.JwtAuthenticationFilter;
import com.marketplace.authentication.security.RefreshTokenJweStringDeserializer;
import com.marketplace.authentication.security.RefreshTokenJweStringSerializer;
import com.marketplace.authentication.security.Token;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig {

    @Value("${jwt.access-token-key}") 
    private String accessTokenKey;

    @Value("${jwt.refresh-token-key}") 
    private String refreshTokenKey;

    @Value("${crypto.base64-secret-key-aes}")
    private String base64SecretKeyAES;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
            .requestMatchers(HttpMethod.GET, "/api/customer-users").authenticated()
            .anyRequest().permitAll())
            .sessionManagement(sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(exception ->
                exception.authenticationEntryPoint((request, response, authException) -> {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
                })) 
            .csrf(CsrfConfigurer::disable);

        return http.build();
    } 

    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TimeBasedOneTimePasswordGenerator totpGenerator() {
        return new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6);
    }

    @Bean 
    public CryptoUtils cryptoUtils() {
        return new CryptoUtils(base64SecretKeyAES);
    }

    @Bean
    public DefaultRefreshTokenFactory defaultRefreshTokenFactory() {
        return new DefaultRefreshTokenFactory();
    }

    @Bean
    public DefaultAccessTokenFactory defaultAccessTokenFactory() {
        return new DefaultAccessTokenFactory();
    }

    @Bean
    @Qualifier("accessTokenJwsStringSerializer")
    public Function<Token, String> accessTokenJwsStringSerializer() {
        try {
            return new AccessTokenJwsStringSerializer(
                new MACSigner(OctetSequenceKey.parse(accessTokenKey))
            );
        } catch (Exception exception) {
            throw new RuntimeException("Ошибка при создании сериализатора accessToken", exception);
        }
    }

    @Bean
    @Qualifier("refreshTokenJweStringSerializer")
    public Function<Token, String> refreshTokenJweStringSerializer() {
        try {
            return new RefreshTokenJweStringSerializer(
                new DirectEncrypter(OctetSequenceKey.parse(refreshTokenKey))
            );
        } catch (Exception exception) {
            throw new RuntimeException("Ошибка при создании сериализатора refreshToken", exception);
        }
    }

    @Bean
    @Qualifier("accessTokenJwsStringDeserializer")
    public Function<String, Token> accessTokenJwsStringDeserializer() {
        try {
            return new AccessTokenJwsStringDeserializer(
                new MACVerifier(OctetSequenceKey.parse(accessTokenKey))
            );
        } catch (Exception exception) {
            throw new RuntimeException("Ошибка при создании десериализатора accessToken", exception);
        }
    }

    @Bean
    @Qualifier("refreshTokenJweStringDeserializer")
    public Function<String, Token> refreshTokenJweStringDeserializer() {
        try {
            return new RefreshTokenJweStringDeserializer(
                new DirectDecrypter(OctetSequenceKey.parse(refreshTokenKey))
            );
        } catch (Exception exception) {
            throw new RuntimeException("Ошибка при создании десериализатора refreshToken", exception);
        }
    }

    @Bean 
    public JwtAuthenticationFilter jwtAuthenticationFilter(
        @Qualifier("accessTokenJwsStringDeserializer") Function<String, Token> accessTokenJwsStringDeserializer,
        UserDetailsService userDetailsService,
        BlacklistTokenService blacklistTokenService
    ) {
        return new JwtAuthenticationFilter(
            accessTokenJwsStringDeserializer, 
            userDetailsService, 
            blacklistTokenService);
    } 
}
