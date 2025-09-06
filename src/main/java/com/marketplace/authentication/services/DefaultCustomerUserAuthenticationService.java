package com.marketplace.authentication.services;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import com.marketplace.authentication.domain.dto.kafka.EmailConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.kafka.PhoneNumberConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.redis.AuthenticatorAppConfirmationCodeAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.CustomerUserAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.EmailConfirmationCodeAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.FailedLoginAttemptsSession;
import com.marketplace.authentication.domain.dto.redis.PhoneNumberConfirmationCodeAuthenticationSession;
import com.marketplace.authentication.domain.dto.request.CustomerUserAuthenticationDto;
import com.marketplace.authentication.domain.dto.response.AuthenticationResponse;
import com.marketplace.authentication.domain.entities.CustomerUser;
import com.marketplace.authentication.exception.exceptions.InvalidConfirmationCodeException;
import com.marketplace.authentication.exception.exceptions.InvalidRefreshTokenException;
import com.marketplace.authentication.exception.exceptions.TooManyAttemptsException;
import com.marketplace.authentication.producers.ConfirmationProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.security.BlacklistTokenService;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.CustomerUserAuthenticationSessionService;
import com.marketplace.authentication.security.FailedLoginAttemptsSessionService;
import com.marketplace.authentication.security.OtpService;
import com.marketplace.authentication.security.Token;
import com.marketplace.authentication.security.Tokens;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DefaultCustomerUserAuthenticationService implements CustomerUserAuthenticationService {

    private final CustomerUserRepository customerUserRepository;
    private final FailedLoginAttemptsSessionService failedLoginAttemptsSessionService;
    private final CustomerUserAuthenticationSessionService customerUserAuthenticationSessionService;
    private final BlacklistTokenService blacklistTokenService;
    private final AuthenticationManager authenticationManager;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;
    private final ConfirmationProducer confirmationProducer;
    private final Function<Authentication, Token> refreshTokenFactory;
    private final Function<Token, Token> accessTokenFactory;
    private final Function<Token, String> refreshTokenJweStringSerializer;
    private final Function<Token, String> accessTokenJwsStringSerializer;
    private final Function<String, Token> refreshTokenJweStringDeserializer;

    @Value("${crypto.secret-key-aes}")
    private String secretKeyAES;

    @Override
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
                failedLoginAttemptsSessionService.saveSession(dto.login(), new FailedLoginAttemptsSession());

                throw new BadCredentialsException(exception.getMessage(), exception);
            }

            session.decrementEntryAttemptsRemaining();
            failedLoginAttemptsSessionService.updateSession(dto.login(), session);

            throw new BadCredentialsException(exception.getMessage(), exception);
        }    

        if (authentication.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenJwsStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenJweStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            CustomerUser customerUser = (CustomerUser) authentication.getPrincipal();
            addTokenInBlacklist(customerUser.getId());
            customerUserRepository.updateTokenId(customerUser.getId(), refreshToken.id().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        UUID sessionId = UUID.randomUUID();

        CustomerUserAuthenticationSession session = 
            new CustomerUserAuthenticationSession((CustomerUser) authentication.getPrincipal());

        customerUserAuthenticationSessionService.
            saveSession(sessionId.toString(), session);

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Override
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
            customerUserAuthenticationSessionService.updateSession(sessionId, session);
            throw new InvalidConfirmationCodeException(exception.getMessage(), exception);
        }

        if (authentication.isAuthenticated()) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenJwsStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenJweStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            CustomerUser customerUser = (CustomerUser) authentication.getPrincipal();
            addTokenInBlacklist(customerUser.getId());
            customerUserRepository.updateTokenId(customerUser.getId(), refreshToken.id().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        session = (CustomerUserAuthenticationSession) authentication;

        session.setEmailConfirmationCode(null);

        customerUserAuthenticationSessionService.
            updateSession(sessionId.toString(), session);

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Override
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
            customerUserAuthenticationSessionService.updateSession(sessionId, session);
            throw new InvalidConfirmationCodeException(exception.getMessage(), exception);
        }

        if (authentication.isAuthenticated()) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenJwsStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenJweStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            CustomerUser customerUser = (CustomerUser) authentication.getPrincipal();
            addTokenInBlacklist(customerUser.getId());
            customerUserRepository.updateTokenId(customerUser.getId(), refreshToken.id().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        session = (CustomerUserAuthenticationSession) authentication;

        session.setPhoneNumberConfirmationCode(null);

        customerUserAuthenticationSessionService.
            updateSession(sessionId.toString(), session);

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Override
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
            customerUserAuthenticationSessionService.updateSession(sessionId, session);
            throw new InvalidConfirmationCodeException(exception.getMessage(), exception);
        }

        if (authentication.isAuthenticated()) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token refreshToken = refreshTokenFactory.apply(authentication);
            Token accessToken = accessTokenFactory.apply(refreshToken);
            Tokens tokens = new Tokens(
                accessTokenJwsStringSerializer.apply(accessToken),
                accessToken.expiresAt().toString(),
                refreshTokenJweStringSerializer.apply(refreshToken),
                refreshToken.expiresAt().toString());

            CustomerUser customerUser = (CustomerUser) authentication.getPrincipal();
            addTokenInBlacklist(customerUser.getId());
            customerUserRepository.updateTokenId(customerUser.getId(), refreshToken.id().toString());

            return new AuthenticationResponse(null, true, true, true, true, tokens);
        }

        session = (CustomerUserAuthenticationSession) authentication;

        session.setAuthenticatorAppConfirmationCode(null);

        customerUserAuthenticationSessionService.
            updateSession(sessionId.toString(), session);

        return new AuthenticationResponse(
            sessionId.toString(),
            session.isAuthenticated(),
            session.isEmailFactorAuthPassed(),
            session.isPhoneNumberFactorAuthPassed(),
            session.isAuthenticatorAppFactorAuthPassed(),
            null
        );
    }

    @Override
    @Transactional
    public void sendEmailConfirmationCodeForAuthSession(String sessionId) {
        CustomerUserAuthenticationSession session = 
            customerUserAuthenticationSessionService.getSession(sessionId);

        if (session.getResendAttemptsRemaining() == 0) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток запросить новые коды подтверждения. Попробуйте позже.");
        }

        session.decrementResendAttemptsRemaining();
        customerUserAuthenticationSessionService.updateSession(sessionId, session);

        String encryptedEmailConfirmationCodeSecret = session.getPrincipal().getEncryptedEmailConfirmationCodeSecret();
        String emailConfirmationCodeSecret = cryptoUtils.decrypt(encryptedEmailConfirmationCodeSecret);

        EmailConfirmationCodeDto emailConfirmationCodeDto = 
            new EmailConfirmationCodeDto(session.getPrincipal().getEmail(), otpService.generateCurrentCode(emailConfirmationCodeSecret));

        confirmationProducer.emailConfirmation(emailConfirmationCodeDto);

        System.out.println("=========================================");
        System.out.println("Почта: " + emailConfirmationCodeDto.code());
        System.out.println("=========================================");
    }

    @Override
    @Transactional
    public void sendPhoneNumberConfirmationCodeForAuthSession(String sessionId) {
        CustomerUserAuthenticationSession session = 
            customerUserAuthenticationSessionService.getSession(sessionId);

        if (session.getResendAttemptsRemaining() == 0) {
            customerUserAuthenticationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток запросить новые коды подтверждения. Попробуйте позже.");
        }

        session.decrementResendAttemptsRemaining();
        customerUserAuthenticationSessionService.updateSession(sessionId, session);

        String encryptedPhoneNumberConfirmationCodeSecret = session.getPrincipal().getEncryptedPhoneNumberConfirmationCodeSecret();
        String phoneNumberConfirmationCodeSecret = cryptoUtils.decrypt(encryptedPhoneNumberConfirmationCodeSecret);

        PhoneNumberConfirmationCodeDto phoneNumberConfirmationCodeDto = 
            new PhoneNumberConfirmationCodeDto(session.getPrincipal().getPhoneNumber(), otpService.generateCurrentCode(phoneNumberConfirmationCodeSecret));

        confirmationProducer.phoneNumberConfirmation(phoneNumberConfirmationCodeDto);

        System.out.println("=========================================");
        System.out.println("Номер: " + phoneNumberConfirmationCodeDto.code());
        System.out.println("=========================================");
    }

    @Override
    public String refreshAccessToken(String refreshToken) {

        Token token = refreshTokenJweStringDeserializer.apply(refreshToken);

        if (token == null) {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }

        Instant now = Instant.now();
        Instant expiration = token.expiresAt();

        if (expiration.isBefore(now)) {
            throw new InvalidRefreshTokenException("Token expired");
        }

        Token accessToken = accessTokenFactory.apply(token);

        return accessTokenJwsStringSerializer.apply(accessToken);
    }

    @Override
    public void logout() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CustomerUser customerUser = (CustomerUser) authentication.getPrincipal();

        blacklistTokenService.saveToken(customerUser.getTokenId());
    }

    private void addTokenInBlacklist(Long id)  {
        String tokenId = customerUserRepository.getTokenId(id);
        blacklistTokenService.saveToken(tokenId);
    }
}
