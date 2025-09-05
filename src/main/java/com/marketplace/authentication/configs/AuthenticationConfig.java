package com.marketplace.authentication.configs;

import java.util.List;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.marketplace.authentication.producers.ConfirmationProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.security.AuthenticatorAppConfirmationCodeAuthenticationProvider;
import com.marketplace.authentication.security.BlacklistTokenService;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.CustomerUserAuthenticationSessionService;
import com.marketplace.authentication.security.DefaultAccessTokenFactory;
import com.marketplace.authentication.security.DefaultAuthenticationManager;
import com.marketplace.authentication.security.DefaultRefreshTokenFactory;
import com.marketplace.authentication.security.EmailConfirmationCodeAuthenticationProvider;
import com.marketplace.authentication.security.FailedLoginAttemptsSessionService;
import com.marketplace.authentication.security.OtpService;
import com.marketplace.authentication.security.PhoneNumberConfirmationCodeAuthenticationProvider;
import com.marketplace.authentication.security.Token;
import com.marketplace.authentication.security.UsernamePasswordAuthenticationProvider;
import com.marketplace.authentication.services.CustomerUserAuthenticationService;
import com.marketplace.authentication.services.DefaultCustomerUserAuthenticationService;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class AuthenticationConfig {

    private final CustomerUserRepository customerUserRepository;
    private final FailedLoginAttemptsSessionService failedLoginAttemptsSessionService;
    private final CustomerUserAuthenticationSessionService customerUserAuthenticationSessionService;
    private final BlacklistTokenService blacklistTokenService;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;
    private final ConfirmationProducer confirmationProducer;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final DefaultRefreshTokenFactory refreshTokenFactory;
    private final DefaultAccessTokenFactory accessTokenFactory;

    @Value("${crypto.secret-key-aes}")
    private String secretKeyAES;

    @Value("${jwt.access-token-key}") 
    private String accessTokenKey;

    @Value("${jwt.refresh-token-key}") 
    private String refreshTokenKey;

    @Bean 
    public AuthenticationProvider usernamePasswordAuthenticationProvider() {
        return new UsernamePasswordAuthenticationProvider(userDetailsService, passwordEncoder);
    }

    @Bean
    public AuthenticationProvider emailConfirmationCodeAuthenticationProvider() {
        return new EmailConfirmationCodeAuthenticationProvider(otpService, cryptoUtils);
    }

    @Bean
    public AuthenticationProvider phoneAuthenticationProvider() {
        return new PhoneNumberConfirmationCodeAuthenticationProvider(otpService, cryptoUtils);
    }

    @Bean
    public AuthenticationProvider appAuthenticationProvider() {
        return new AuthenticatorAppConfirmationCodeAuthenticationProvider(otpService, cryptoUtils);
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        return new DefaultAuthenticationManager(providers);
    }

    @Bean
    public CustomerUserAuthenticationService customerUserAuthenticationService(
        @Qualifier("refreshTokenJweStringSerializer") Function<Token, String> refreshTokenJweStringSerializer,
        @Qualifier("accessTokenJwsStringSerializer") Function<Token, String> accessTokenJwsStringSerializer,
        @Qualifier("refreshTokenJweStringDeserializer") Function<String, Token> refreshTokenJweStringDeserializer,
        AuthenticationManager authenticationManager
    ) {
        return new DefaultCustomerUserAuthenticationService(
            customerUserRepository,
            failedLoginAttemptsSessionService,
            customerUserAuthenticationSessionService,
            blacklistTokenService,
            authenticationManager,
            otpService,
            cryptoUtils,
            confirmationProducer,
            refreshTokenFactory,
            accessTokenFactory,
            refreshTokenJweStringSerializer,
            accessTokenJwsStringSerializer,
            refreshTokenJweStringDeserializer
        );
    }
}
