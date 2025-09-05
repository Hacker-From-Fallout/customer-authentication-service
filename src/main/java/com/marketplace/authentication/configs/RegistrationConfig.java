package com.marketplace.authentication.configs;

import java.util.function.Function;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.marketplace.authentication.producers.ConfirmationProducer;
import com.marketplace.authentication.producers.CustomerUserProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.CustomerUserRegistrationSessionService;
import com.marketplace.authentication.security.DefaultAccessTokenFactory;
import com.marketplace.authentication.security.DefaultRefreshTokenFactory;
import com.marketplace.authentication.security.OtpService;
import com.marketplace.authentication.security.Token;
import com.marketplace.authentication.services.CustomerUserRegistrationService;
import com.marketplace.authentication.services.CustomerUserService;
import com.marketplace.authentication.services.DefaultCustomerUserRegistrationService;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class RegistrationConfig {

    private final CustomerUserService customerUserService;
    private final CustomerUserRegistrationSessionService customerUserRegistrationSessionService;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;
    private final ConfirmationProducer confirmationProducer;
    private final CustomerUserRepository customerUserRepository;
    private final CustomerUserProducer customerUserProducer;
    private final PasswordEncoder passwordEncoder;
    private final DefaultRefreshTokenFactory refreshTokenFactory;
    private final DefaultAccessTokenFactory accessTokenFactory;

    @Value("${crypto.secret-key-aes}")
    private String secretKeyAES;

    @Value("${jwt.access-token-key}") 
    private String accessTokenKey;

    @Value("${jwt.refresh-token-key}") 
    private String refreshTokenKey;

    @Bean CustomerUserRegistrationService customerUserRegistrationService(
        @Qualifier("refreshTokenStringSerializer") Function<Token, String> refreshTokenStringSerializer,
        @Qualifier("accessTokenStringSerializer") Function<Token, String> accessTokenStringSerializer
    ) {
        return new DefaultCustomerUserRegistrationService(
            customerUserService,
            customerUserRegistrationSessionService,
            otpService,
            cryptoUtils,
            confirmationProducer,
            customerUserRepository,
            customerUserProducer,
            passwordEncoder,
            refreshTokenFactory,
            accessTokenFactory,
            refreshTokenStringSerializer,
            accessTokenStringSerializer
        );
    }
}
