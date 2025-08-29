package com.marketplace.authentication.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.marketplace.authentication.domain.dto.redis.PhoneNumberConfirmationCodeAuthenticationSession;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class PhoneNumberConfirmationCodeAuthenticationProvider implements AuthenticationProvider {

    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PhoneNumberConfirmationCodeAuthenticationSession session = 
            (PhoneNumberConfirmationCodeAuthenticationSession) authentication;

        String encryptedPhoneNumberConfirmationCodeSecret = 
            session.getPrincipal().getEncryptedPhoneNumberConfirmationCodeSecret();

        String phoneNumberConfirmationCodeSecret = 
            cryptoUtils.decrypt(encryptedPhoneNumberConfirmationCodeSecret);

        boolean phoneNumberConfirmationCodeSecretValid = 
            otpService.verifyCode(session.getPhoneNumberConfirmationCode(), phoneNumberConfirmationCodeSecret);

        if (phoneNumberConfirmationCodeSecretValid) {
            session.setPhoneNumberFactorAuthPassed(true);
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
        return PhoneNumberConfirmationCodeAuthenticationSession.class.isAssignableFrom(authentication);
    }
}
