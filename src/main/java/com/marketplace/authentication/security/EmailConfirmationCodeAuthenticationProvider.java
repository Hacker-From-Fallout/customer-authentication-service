package com.marketplace.authentication.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.marketplace.authentication.domain.dto.redis.EmailConfirmationCodeAuthenticationSession;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EmailConfirmationCodeAuthenticationProvider implements AuthenticationProvider {

    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        EmailConfirmationCodeAuthenticationSession session = 
            (EmailConfirmationCodeAuthenticationSession) authentication;

        String encryptedEmailConfirmationCodeSecret = 
            session.getPrincipal().getEncryptedEmailConfirmationCodeSecret();

        String emailConfirmationCodeSecret = cryptoUtils.decrypt(encryptedEmailConfirmationCodeSecret);

        boolean emailConfirmationCodeValid = 
            otpService.verifyCode(session.getEmailConfirmationCode(), emailConfirmationCodeSecret);

        if (emailConfirmationCodeValid) {
            session.setEmailFactorAuthPassed(true);
        } else {
            throw new BadCredentialsException("Неверный код подтверждения");
        }

        if(session.isMultiFactorAuthPassed()) {
            session.setAuthenticated(true);
            return session;
        }

        return session;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return EmailConfirmationCodeAuthenticationSession.class.isAssignableFrom(authentication);
    }
}
