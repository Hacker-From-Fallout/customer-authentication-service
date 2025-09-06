package com.marketplace.authentication.configs;

import java.util.function.Function;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.marketplace.authentication.producers.ConfirmationProducer;
import com.marketplace.authentication.producers.CustomerProfileProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.RegistrationSessionService;
import com.marketplace.authentication.security.DefaultAccessTokenFactory;
import com.marketplace.authentication.security.DefaultRefreshTokenFactory;
import com.marketplace.authentication.security.OtpService;
import com.marketplace.authentication.security.Token;
import com.marketplace.authentication.services.RegistrationService;
import com.marketplace.authentication.services.CustomerUserService;
import com.marketplace.authentication.services.DefaultRegistrationService;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class RegistrationConfig {

    private final CustomerUserService customerUserService;
    private final RegistrationSessionService registrationSessionService;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;
    private final ConfirmationProducer confirmationProducer;
    private final CustomerUserRepository customerUserRepository;
    private final CustomerProfileProducer customerProfileProducer;
    private final PasswordEncoder passwordEncoder;
    private final DefaultRefreshTokenFactory refreshTokenFactory;
    private final DefaultAccessTokenFactory accessTokenFactory;

    @Bean RegistrationService customerUserRegistrationService(
        @Qualifier("refreshTokenJweStringSerializer") Function<Token, String> refreshTokenJweStringSerializer,
        @Qualifier("accessTokenJwsStringSerializer") Function<Token, String> accessTokenJwsStringSerializer
    ) {
        return new DefaultRegistrationService(
            customerUserService,
            registrationSessionService,
            otpService,
            cryptoUtils,
            confirmationProducer,
            customerUserRepository,
            customerProfileProducer,
            passwordEncoder,
            refreshTokenFactory,
            accessTokenFactory,
            refreshTokenJweStringSerializer,
            accessTokenJwsStringSerializer
        );
    }
}
