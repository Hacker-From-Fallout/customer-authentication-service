package com.marketplace.authentication.services;

import java.time.Duration;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.marketplace.authentication.domain.dto.kafka.CustomerProfileCreateDto;
import com.marketplace.authentication.domain.dto.kafka.EmailConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.kafka.PhoneNumberConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.redis.AuthenticatorAppConfirmationCodeAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.CustomerUserAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;
import com.marketplace.authentication.domain.dto.redis.EmailConfirmationCodeAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.FailedLoginAttemptsSession;
import com.marketplace.authentication.domain.dto.redis.PhoneNumberConfirmationCodeAuthenticationSession;
import com.marketplace.authentication.domain.dto.request.CustomerUserAuthenticationDto;
import com.marketplace.authentication.domain.dto.request.ConfirmationRegistrarionCodesDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.dto.response.AuthenticationResponse;
import com.marketplace.authentication.domain.entities.CustomerUser;
import com.marketplace.authentication.exception.exceptions.InvalidConfirmationCodeException;
import com.marketplace.authentication.exception.exceptions.TooManyAttemptsException;
import com.marketplace.authentication.exception.exceptions.VerificationRegistrationCodesException;
import com.marketplace.authentication.producers.ConfirmationProducer;
import com.marketplace.authentication.producers.CustomerUserProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.CustomerUserAuthenticationSessionService;
import com.marketplace.authentication.security.CustomerUserRegistrationSessionService;
import com.marketplace.authentication.security.DefaultAccessTokenFactory;
import com.marketplace.authentication.security.DefaultRefreshTokenFactory;
import com.marketplace.authentication.security.FailedLoginAttemptsSessionService;
import com.marketplace.authentication.security.OtpService;
import com.marketplace.authentication.security.Token;
import com.marketplace.authentication.security.Tokens;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class CustomerUserAuthenticationService {

    private final CustomerUserService customerUserService;
    private final FailedLoginAttemptsSessionService failedLoginAttemptsSessionService;
    private final CustomerUserRegistrationSessionService customerUserRegistrationSessionService;
    private final CustomerUserAuthenticationSessionService customerUserAuthenticationSessionService;
    private final AuthenticationManager authenticationManager;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;
    private final ConfirmationProducer confirmationProducer;
    private final CustomerUserRepository customerUserRepository;
    private final CustomerUserProducer customerUserProducer;
    private final PasswordEncoder passwordEncoder;
    private final Function<Authentication, Token> refreshTokenFactory;
    private final Function<Token, Token> accessTokenFactory;
    private final Function<Token, String> refreshTokenStringSerializer;
    private final Function<Token, String> accessTokenStringSerializer;

    @Value("${crypto.secret-key-aes}")
    private String secretKeyAES;

    public CustomerUserAuthenticationService(
        CustomerUserService customerUserService,
        FailedLoginAttemptsSessionService failedLoginAttemptsSessionService,
        CustomerUserRegistrationSessionService customerUserRegistrationSessionService,
        CustomerUserAuthenticationSessionService customerUserAuthenticationSessionService,
        AuthenticationManager authenticationManager,
        OtpService otpService,
        CryptoUtils cryptoUtils,
        ConfirmationProducer confirmationProducer,
        CustomerUserRepository customerUserRepository,
        CustomerUserProducer customerUserProducer,
        PasswordEncoder passwordEncoder,
        @Qualifier("refreshTokenStringSerializer") Function<Token, String> refreshTokenStringSerializer,
        @Qualifier("accessTokenStringSerializer") Function<Token, String> accessTokenStringSerializer
    ) {
        this.customerUserService = customerUserService;
        this.failedLoginAttemptsSessionService = failedLoginAttemptsSessionService;
        this.customerUserRegistrationSessionService = customerUserRegistrationSessionService;
        this.customerUserAuthenticationSessionService = customerUserAuthenticationSessionService;
        this.authenticationManager = authenticationManager;
        this.otpService = otpService;
        this.cryptoUtils = cryptoUtils;
        this.confirmationProducer = confirmationProducer;
        this.customerUserRepository = customerUserRepository;
        this.customerUserProducer = customerUserProducer;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenFactory = new DefaultRefreshTokenFactory();
        this.accessTokenFactory = new DefaultAccessTokenFactory();
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    @Transactional
    public UUID initiateRegistration(CustomerUserCreateDto dto) {
        customerUserService.isUsernameEmailPhoneAvailable(dto.username(), dto.email(), dto.phoneNumber());

        UUID sessionId = UUID.randomUUID();
        String emailConfirmationCodeSecret = otpService.generateSecret();
        String phoneNumberConfirmationCodeSecret = otpService.generateSecret();
        EmailConfirmationCodeDto emailConfirmationCodeDto = 
            new EmailConfirmationCodeDto(dto.email(), 
                otpService.generateCurrentCode(emailConfirmationCodeSecret));
        PhoneNumberConfirmationCodeDto phoneNumberConfirmationCodeDto = 
            new PhoneNumberConfirmationCodeDto(dto.phoneNumber(),
                otpService.generateCurrentCode(phoneNumberConfirmationCodeSecret));
        String encryptedEmailConfirmationCodeSecret = cryptoUtils.encrypt(emailConfirmationCodeSecret);
        String encryptedPhoneNumberConfirmationCodeSecret = cryptoUtils.encrypt(phoneNumberConfirmationCodeSecret);

        CustomerUserRegistrationSession session = CustomerUserRegistrationSession.builder()
            .firstName(dto.firstName())
            .lastName(dto.lastName())
            .username(dto.username())
            .email(dto.email())
            .phoneNumber(dto.phoneNumber())
            .hashPassword(passwordEncoder.encode(dto.password()))
            .roles(dto.roles())
            .authorities(dto.authorities())
            .accountNonExpired(dto.accountNonExpired())
            .accountNonLocked(dto.accountNonLocked())
            .credentialsNonExpired(dto.credentialsNonExpired())
            .enabled(dto.enabled())
            .emailFactorAuthEnabled(dto.emailFactorAuthEnabled())
            .phoneNumberFactorAuthEnabled(dto.phoneNumberFactorAuthEnabled())
            .authenticatorAppFactorAuthEnabled(dto.authenticatorAppFactorAuthEnabled())
            .encryptedEmailConfirmationCodeSecret(encryptedEmailConfirmationCodeSecret)
            .encryptedPhoneNumberConfirmationCodeSecret(encryptedPhoneNumberConfirmationCodeSecret)
            .build();

        customerUserRegistrationSessionService.saveSession(sessionId.toString(), session, Duration.ofMinutes(5));

        confirmationProducer.emailConfirmation(emailConfirmationCodeDto);
        confirmationProducer.phoneNumberConfirmation(phoneNumberConfirmationCodeDto);

        System.out.println("=========================================");
        System.out.println("Почта: " + emailConfirmationCodeDto.code());
        System.out.println("Номер: " + phoneNumberConfirmationCodeDto.code());
        System.out.println("=========================================");

        return sessionId;
    }

    @Transactional
    public Tokens confirmationRegistration(String sessionId, ConfirmationRegistrarionCodesDto dto) {

        CustomerUserRegistrationSession session = customerUserRegistrationSessionService.getSession(sessionId);

        if (session.getCodeEntryAttemptsRemaining() == 0) {
            customerUserRegistrationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток ввода кода. Попробуйте позже.");
        }

        String encryptedEmailConfirmationCodeSecret = session.getEncryptedEmailConfirmationCodeSecret();
        String encryptedPhoneNumberConfirmationCodeSecret = session.getEncryptedPhoneNumberConfirmationCodeSecret();
        String emailConfirmationCodeSecret = cryptoUtils.decrypt(encryptedEmailConfirmationCodeSecret);
        String phoneNumberConfirmationCodeSecret = cryptoUtils.decrypt(encryptedPhoneNumberConfirmationCodeSecret);

        boolean emailConfirmationCodeValid = 
            otpService.verifyCode(dto.emailConfirmationCode(), emailConfirmationCodeSecret);
        boolean phoneNumberConfirmationCodeValid = 
            otpService.verifyCode(dto.phoneNumberConfirmationCode(), phoneNumberConfirmationCodeSecret);

        if (!(emailConfirmationCodeValid && phoneNumberConfirmationCodeValid)) {
            session.decrementCodeEntryAttempts();
            customerUserRegistrationSessionService.updateSession(sessionId, session, Duration.ofMinutes(5));
            throw new VerificationRegistrationCodesException("Коды просрочены или введены неправильно.");
        }

        CustomerUser customerUser = CustomerUser.builder()
            .username(session.getUsername())
            .email(session.getEmail())
            .phoneNumber(session.getPhoneNumber())
            .hashPassword(session.getHashPassword())
            .roles(session.getRoles())
            .authorities(session.getAuthorities())
            .accountNonExpired(session.isAccountNonExpired())
            .accountNonLocked(session.isAccountNonLocked())
            .credentialsNonExpired(session.isCredentialsNonExpired())
            .enabled(session.isEnabled())
            .emailFactorAuthEnabled(session.isEmailFactorAuthEnabled())
            .phoneNumberFactorAuthEnabled(session.isPhoneNumberFactorAuthEnabled())
            .authenticatorAppFactorAuthEnabled(session.isAuthenticatorAppFactorAuthEnabled())
            .build();

        customerUser = customerUserRepository.save(customerUser);

        CustomerProfileCreateDto profileDto = new CustomerProfileCreateDto(
            customerUser.getId(),
            session.getFirstName(),
            session.getLastName(),
            session.getUsername(),
            session.getEmail(),
            session.getPhoneNumber());

        customerUserProducer.createProfile(profileDto);
        customerUserRegistrationSessionService.deleteSession(sessionId);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
            customerUser,
            null,
            customerUser.getAuthorities()
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        Token refreshToken = refreshTokenFactory.apply(authentication);
        Token accessToken = accessTokenFactory.apply(refreshToken);
        Tokens tokens = new Tokens(
            accessTokenStringSerializer.apply(accessToken),
            accessToken.expiresAt().toString(),
            refreshTokenStringSerializer.apply(refreshToken),
            refreshToken.expiresAt().toString());

        return tokens;
    }

    @Transactional
    public void resendConfirmationRegistrationCodes(String sessionId) {

        CustomerUserRegistrationSession session = customerUserRegistrationSessionService.getSession(sessionId);

        if (session.getResendAttemptsRemaining() == 0) {
            customerUserRegistrationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток запросить новые коды подтверждения. Попробуйте позже.");
        }

        session.decrementResendAttemptsRemaining();
        customerUserRegistrationSessionService.updateSession(sessionId, session, Duration.ofMinutes(5));

        String encryptedEmailConfirmationCodeSecret = session.getEncryptedEmailConfirmationCodeSecret();
        String encryptedPhoneNumberConfirmationCodeSecret = session.getEncryptedPhoneNumberConfirmationCodeSecret();
        String emailConfirmationCodeSecret = cryptoUtils.decrypt(encryptedEmailConfirmationCodeSecret);
        String phoneNumberConfirmationCodeSecret = cryptoUtils.decrypt(encryptedPhoneNumberConfirmationCodeSecret);

        EmailConfirmationCodeDto emailConfirmationCodeDto = 
            new EmailConfirmationCodeDto(session.getEmail(), otpService.generateCurrentCode(emailConfirmationCodeSecret));
        PhoneNumberConfirmationCodeDto phoneNumberConfirmationCodeDto = 
            new PhoneNumberConfirmationCodeDto(session.getPhoneNumber(), otpService.generateCurrentCode(phoneNumberConfirmationCodeSecret));
        confirmationProducer.emailConfirmation(emailConfirmationCodeDto);
        confirmationProducer.phoneNumberConfirmation(phoneNumberConfirmationCodeDto);

        System.out.println("=========================================");
        System.out.println("Почта: " + emailConfirmationCodeDto.code());
        System.out.println("Номер: " + phoneNumberConfirmationCodeDto.code());
        System.out.println("=========================================");
    }

    @Transactional
    public AuthenticationResponse usernamePasswordAuthenticate(CustomerUserAuthenticationDto dto) {

        FailedLoginAttemptsSession failedLoginAttemptsSession = 
            failedLoginAttemptsSessionService.getSession(dto.login());

        if (failedLoginAttemptsSession != null) {
            if (failedLoginAttemptsSession.getEntryAttemptsRemaining() == 0) {
                throw new TooManyAttemptsException("Достигнут лимит попыток войти в аккаунт. Попробуйте позже.");
            }
        }

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
            new UsernamePasswordAuthenticationToken(dto.login(), dto.password());

        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (BadCredentialsException exception) {

            FailedLoginAttemptsSession session = failedLoginAttemptsSessionService.getSession(dto.login());

            if (session == null) {
                failedLoginAttemptsSessionService.saveSession(
                    dto.login(), 
                    new FailedLoginAttemptsSession(),
                    Duration.ofMinutes(60)
                );

                throw new BadCredentialsException(exception.getMessage(), exception);
            }

            session.decrementEntryAttemptsRemaining();
            failedLoginAttemptsSessionService.updateSession(dto.login(), session, Duration.ofMinutes(60));

            throw new BadCredentialsException(exception.getMessage(), exception);
        }    

        if (authentication.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        UUID sessionId = UUID.randomUUID();

        CustomerUserAuthenticationSession session = 
            new CustomerUserAuthenticationSession((CustomerUser) authentication.getPrincipal());

        customerUserAuthenticationSessionService.
            saveSession(sessionId.toString(), session, Duration.ofMinutes(5));

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Transactional
    public AuthenticationResponse emailConfirmationCodeAuthenticate(String sessionId, String confirmationCode) {
        CustomerUserAuthenticationSession session = 
            customerUserAuthenticationSessionService.getSession(sessionId);

        if (session.getCodeEntryAttemptsRemaining() == 0) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток ввода кода. Попробуйте позже.");
        }

        session.setEmailConfirmationCode(confirmationCode);

        EmailConfirmationCodeAuthenticationSession authenticationSession =
            new EmailConfirmationCodeAuthenticationSession(session);

        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(authenticationSession);
        } catch (BadCredentialsException exception) {
            session.decrementCodeEntryAttempts();
            customerUserAuthenticationSessionService.updateSession(sessionId, session, Duration.ofMinutes(5));
            throw new InvalidConfirmationCodeException(exception.getMessage(), exception);
        }

        if (authentication.isAuthenticated()) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        session = (CustomerUserAuthenticationSession) authentication;

        session.setEmailConfirmationCode(null);

        customerUserAuthenticationSessionService.
            updateSession(sessionId.toString(), session, Duration.ofMinutes(5));

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Transactional
    public AuthenticationResponse phoneNumberConfirmationCodeAuthenticate(String sessionId, String confirmationCode) {
        CustomerUserAuthenticationSession session = 
            customerUserAuthenticationSessionService.getSession(sessionId);

        if (session.getCodeEntryAttemptsRemaining() == 0) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток ввода кода. Попробуйте позже.");
        }

        session.setPhoneNumberConfirmationCode(confirmationCode);

        PhoneNumberConfirmationCodeAuthenticationSession authenticationSession =
            new PhoneNumberConfirmationCodeAuthenticationSession(session);

        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(authenticationSession);
        } catch (BadCredentialsException exception) {
            session.decrementCodeEntryAttempts();
            customerUserAuthenticationSessionService.updateSession(sessionId, session, Duration.ofMinutes(5));
            throw new InvalidConfirmationCodeException(exception.getMessage(), exception);
        }

        if (authentication.isAuthenticated()) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        session = (CustomerUserAuthenticationSession) authentication;

        session.setPhoneNumberConfirmationCode(null);

        customerUserAuthenticationSessionService.
            updateSession(sessionId.toString(), session, Duration.ofMinutes(5));

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Transactional
    public AuthenticationResponse authenticatorAppConfirmationCodeAuthenticate(String sessionId, String confirmationCode) {
        CustomerUserAuthenticationSession session = 
            customerUserAuthenticationSessionService.getSession(sessionId);

        if (session.getCodeEntryAttemptsRemaining() == 0) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток ввода кода. Попробуйте позже.");
        }

        session.setAuthenticatorAppConfirmationCode(confirmationCode);

        AuthenticatorAppConfirmationCodeAuthenticationSession authenticationSession =
            new AuthenticatorAppConfirmationCodeAuthenticationSession(session);

        System.out.print(authenticationSession.isEmailFactorAuthPassed());

        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(authenticationSession);
        } catch (BadCredentialsException exception) {
            session.decrementCodeEntryAttempts();
            customerUserAuthenticationSessionService.updateSession(sessionId, session, Duration.ofMinutes(5));
            throw new InvalidConfirmationCodeException(exception.getMessage(), exception);
        }

        if (authentication.isAuthenticated()) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        session = (CustomerUserAuthenticationSession) authentication;

        session.setAuthenticatorAppConfirmationCode(null);

        customerUserAuthenticationSessionService.
            updateSession(sessionId.toString(), session, Duration.ofMinutes(5));

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Transactional
    public void sendEmailConfirmationCodeForAuthSession(String sessionId) {
        CustomerUserAuthenticationSession session = 
            customerUserAuthenticationSessionService.getSession(sessionId);

        if (session.getResendAttemptsRemaining() == 0) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток запросить новые коды подтверждения. Попробуйте позже.");
        }

        session.decrementResendAttemptsRemaining();
        customerUserAuthenticationSessionService.updateSession(sessionId, session, Duration.ofMinutes(5));

        String encryptedEmailConfirmationCodeSecret = session.getPrincipal().getEncryptedEmailConfirmationCodeSecret();
        String emailConfirmationCodeSecret = cryptoUtils.decrypt(encryptedEmailConfirmationCodeSecret);

        EmailConfirmationCodeDto emailConfirmationCodeDto = 
            new EmailConfirmationCodeDto(session.getPrincipal().getEmail(), otpService.generateCurrentCode(emailConfirmationCodeSecret));

        confirmationProducer.emailConfirmation(emailConfirmationCodeDto);

        System.out.println("=========================================");
        System.out.println("Почта: " + emailConfirmationCodeDto.code());
        System.out.println("=========================================");
    }

    @Transactional
    public void sendPhoneNumberConfirmationCodeForAuthSession(String sessionId) {
        CustomerUserAuthenticationSession session = 
            customerUserAuthenticationSessionService.getSession(sessionId);

        if (session.getResendAttemptsRemaining() == 0) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток запросить новые коды подтверждения. Попробуйте позже.");
        }

        session.decrementResendAttemptsRemaining();
        customerUserAuthenticationSessionService.updateSession(sessionId, session, Duration.ofMinutes(5));

        String encryptedPhoneNumberConfirmationCodeSecret = session.getPrincipal().getEncryptedPhoneNumberConfirmationCodeSecret();
        String phoneNumberConfirmationCodeSecret = cryptoUtils.decrypt(encryptedPhoneNumberConfirmationCodeSecret);

        PhoneNumberConfirmationCodeDto phoneNumberConfirmationCodeDto = 
            new PhoneNumberConfirmationCodeDto(session.getPrincipal().getPhoneNumber(), otpService.generateCurrentCode(phoneNumberConfirmationCodeSecret));

        confirmationProducer.phoneNumberConfirmation(phoneNumberConfirmationCodeDto);

        System.out.println("=========================================");
        System.out.println("Номер: " + phoneNumberConfirmationCodeDto.code());
        System.out.println("=========================================");
    }
}
