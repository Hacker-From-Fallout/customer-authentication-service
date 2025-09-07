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

    // @Bean
    // public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
    //     http
    //         .authorizeHttpRequests(authorize -> authorize
    //             // CustomerUserController endpoints
    //             .requestMatchers(HttpMethod.GET, "/api").hasAnyAuthority("CUSTOMER_USER_GET_ALL")
    //             .requestMatchers(HttpMethod.GET, "/api/{id}").hasAnyAuthority("CUSTOMER_USER_GET_BY_ID")
    //             .requestMatchers(HttpMethod.GET, "/api/username/{username}").hasAnyAuthority("CUSTOMER_USER_GET_BY_USERNAME")
    //             .requestMatchers(HttpMethod.GET, "/api/email/{email}").hasAnyAuthority("CUSTOMER_USER_GET_BY_EMAIL")
    //             .requestMatchers(HttpMethod.GET, "/api/phone/{phoneNumber}").hasAnyAuthority("CUSTOMER_USER_GET_BY_PHONE")
    //             .requestMatchers(HttpMethod.POST, "/api").hasAnyAuthority("CUSTOMER_USER_CREATE")
    //             .requestMatchers(HttpMethod.PUT, "/api/{id}").hasAnyAuthority("CUSTOMER_USER_UPDATE")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/username").hasAnyAuthority("CUSTOMER_USER_UPDATE_USERNAME")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/email").hasAnyAuthority("CUSTOMER_USER_UPDATE_EMAIL")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/phone-number").hasAnyAuthority("CUSTOMER_USER_UPDATE_PHONE")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/password").hasAnyAuthority("CUSTOMER_USER_UPDATE_PASSWORD")
    //             .requestMatchers(HttpMethod.PUT, "/api/{userId}/roles").hasAnyAuthority("CUSTOMER_USER_UPDATE_ROLES")
    //             .requestMatchers(HttpMethod.PUT, "/api/{userId}/authorities").hasAnyAuthority("CUSTOMER_USER_UPDATE_AUTHORITIES")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/accountNonExpired").hasAnyAuthority("CUSTOMER_USER_UPDATE_ACCOUNT_NON_EXPIRED")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/account-non-locked").hasAnyAuthority("CUSTOMER_USER_UPDATE_ACCOUNT_NON_LOCKED")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/credentials-non-expired").hasAnyAuthority("CUSTOMER_USER_UPDATE_CREDENTIALS_NON_EXPIRED")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/enabled").hasAnyAuthority("CUSTOMER_USER_UPDATE_ENABLED")
    //             .requestMatchers(HttpMethod.POST, "/api/{id}/email-factor-auth-enable").hasAnyAuthority("CUSTOMER_USER_ENABLE_EMAIL_FACTOR_AUTH")
    //             .requestMatchers(HttpMethod.POST, "/api/{id}/email-factor-auth-disable").hasAnyAuthority("CUSTOMER_USER_DISABLE_EMAIL_FACTOR_AUTH")
    //             .requestMatchers(HttpMethod.POST, "/api/{id}/phone-number-factor-auth-enable").hasAnyAuthority("CUSTOMER_USER_ENABLE_PHONE_FACTOR_AUTH")
    //             .requestMatchers(HttpMethod.POST, "/api/{id}/phone-number-factor-auth-disable").hasAnyAuthority("CUSTOMER_USER_DISABLE_PHONE_FACTOR_AUTH")
    //             .requestMatchers(HttpMethod.POST, "/api/{id}/authenticator-app-factor-auth-enable").hasAnyAuthority("CUSTOMER_USER_ENABLE_AUTH_APP_FACTOR_AUTH")
    //             .requestMatchers(HttpMethod.POST, "/api/{id}/authenticator-app-factor-auth-disable").hasAnyAuthority("CUSTOMER_USER_DISABLE_AUTH_APP_FACTOR_AUTH")
    //             .requestMatchers(HttpMethod.PATCH, "/api/{id}/last-login-date").hasAnyAuthority("CUSTOMER_USER_UPDATE_LAST_LOGIN_DATE")
    //             .requestMatchers(HttpMethod.POST, "/api/{userId}/roles").hasAnyAuthority("CUSTOMER_USER_ADD_ROLE")
    //             .requestMatchers(HttpMethod.POST, "/api/{userId}/roles/batch").hasAnyAuthority("CUSTOMER_USER_ADD_ROLES")
    //             .requestMatchers(HttpMethod.DELETE, "/api/{userId}/roles").hasAnyAuthority("CUSTOMER_USER_REMOVE_ROLE")
    //             .requestMatchers(HttpMethod.DELETE, "/api/{userId}/roles/batch").hasAnyAuthority("CUSTOMER_USER_REMOVE_ROLES")
    //             .requestMatchers(HttpMethod.POST, "/api/{userId}/authorities").hasAnyAuthority("CUSTOMER_USER_ADD_AUTHORITY")
    //             .requestMatchers(HttpMethod.POST, "/api/{userId}/authorities/batch").hasAnyAuthority("CUSTOMER_USER_ADD_AUTHORITIES")
    //             .requestMatchers(HttpMethod.DELETE, "/api/{userId}/authorities").hasAnyAuthority("CUSTOMER_USER_REMOVE_AUTHORITY")
    //             .requestMatchers(HttpMethod.DELETE, "/api/{userId}/authorities/batch").hasAnyAuthority("CUSTOMER_USER_REMOVE_AUTHORITIES")
    //             .requestMatchers(HttpMethod.DELETE, "/api/{id}").hasAnyAuthority("CUSTOMER_USER_DELETE")

    //             // AuthenticationController endpoints
    //             .requestMatchers(HttpMethod.POST, "/api/auth/initiate-registration").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/confirmation-registration/{sessionId}").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/resend-confirmation-registration/{sessionId}").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/login").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/confirmation-email/{sessionId}").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/confirmation-phone-number/{sessionId}").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/confirmation-authenticator-app/{sessionId}").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/send-email-code/{sessionId}").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/send-phone-number-code/{sessionId}").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/refresh-access-token").anonymous()
    //             .requestMatchers(HttpMethod.POST, "/api/auth/logout").hasAnyAuthority("AUTH_LOGOUT")

    //             .anyRequest().permitAll()
    //         )
    //         .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    //         .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
    //         .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, authException) -> {
    //             response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
    //         }))
    //         .csrf(CsrfConfigurer::disable);

    //     return http.build();
    // }

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
