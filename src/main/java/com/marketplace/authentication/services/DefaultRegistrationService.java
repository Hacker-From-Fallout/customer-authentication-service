package com.marketplace.authentication.services;

import java.util.UUID;
import java.util.function.Function;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import com.marketplace.authentication.domain.dto.kafka.CustomerProfileCreateDto;
import com.marketplace.authentication.domain.dto.kafka.EmailConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.kafka.PhoneNumberConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.redis.RegistrationSession;
import com.marketplace.authentication.domain.dto.request.ConfirmationRegistrarionCodesDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.entities.CustomerUser;
import com.marketplace.authentication.exception.exceptions.TooManyAttemptsException;
import com.marketplace.authentication.exception.exceptions.VerificationRegistrationCodesException;
import com.marketplace.authentication.producers.ConfirmationProducer;
import com.marketplace.authentication.producers.CustomerProfileProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.RegistrationSessionService;
import com.marketplace.authentication.security.OtpService;
import com.marketplace.authentication.security.Token;
import com.marketplace.authentication.security.Tokens;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DefaultRegistrationService implements RegistrationService {

    private final CustomerUserService customerUserService;
    private final RegistrationSessionService registrationSessionService;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;
    private final ConfirmationProducer confirmationProducer;
    private final CustomerUserRepository customerUserRepository;
    private final CustomerProfileProducer customerProfileProducer;
    private final PasswordEncoder passwordEncoder;
    private final Function<Authentication, Token> refreshTokenFactory;
    private final Function<Token, Token> accessTokenFactory;
    private final Function<Token, String> refreshTokenStringSerializer;
    private final Function<Token, String> accessTokenStringSerializer;

    @Override
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

        RegistrationSession session = RegistrationSession.builder()
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

        registrationSessionService.saveSession(sessionId.toString(), session);

        confirmationProducer.emailConfirmation(emailConfirmationCodeDto);
        confirmationProducer.phoneNumberConfirmation(phoneNumberConfirmationCodeDto);

        System.out.println("=========================================");
        System.out.println("Почта: " + emailConfirmationCodeDto.code());
        System.out.println("Номер: " + phoneNumberConfirmationCodeDto.code());
        System.out.println("=========================================");

        return sessionId;
    }

    @Override
    @Transactional
    public Tokens confirmationRegistration(String sessionId, ConfirmationRegistrarionCodesDto dto) {

        RegistrationSession session = registrationSessionService.getSession(sessionId);

        if (session.getCodeEntryAttemptsRemaining() == 0) {
            registrationSessionService.deleteSession(sessionId);
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
            registrationSessionService.updateSession(sessionId, session);
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

        customerProfileProducer.createProfile(profileDto);
        registrationSessionService.deleteSession(sessionId);

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

        customerUserRepository.updateTokenId(customerUser.getId(), refreshToken.id().toString());

        return tokens;
    }

    @Override
    @Transactional
    public void resendConfirmationRegistrationCodes(String sessionId) {

        RegistrationSession session = registrationSessionService.getSession(sessionId);

        if (session.getResendAttemptsRemaining() == 0) {
            registrationSessionService.deleteSession(sessionId);
            throw new TooManyAttemptsException("Достигнут лимит попыток запросить новые коды подтверждения. Попробуйте позже.");
        }

        session.decrementResendAttemptsRemaining();
        registrationSessionService.updateSession(sessionId, session);

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
}
