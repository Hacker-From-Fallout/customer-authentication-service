package com.marketplace.authentication.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.marketplace.authentication.domain.dto.redis.AuthenticatorAppConfirmationCodeAuthenticationSession;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthenticatorAppConfirmationCodeAuthenticationProvider implements AuthenticationProvider {

    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthenticatorAppConfirmationCodeAuthenticationSession session = 
            (AuthenticatorAppConfirmationCodeAuthenticationSession) authentication;

        String encryptedAuthenticatorAppConfirmationCodeSecret = 
            session.getPrincipal().getEncryptedAuthenticatorAppConfirmationCodeSecret();

        String authenticatorAppConfirmationCodeSecret = 
            cryptoUtils.decrypt(encryptedAuthenticatorAppConfirmationCodeSecret);

        boolean authenticatorAppConfirmationCodeValid = 
            otpService.verifyCode(session.getAuthenticatorAppConfirmationCode(), 
                authenticatorAppConfirmationCodeSecret);

        if (authenticatorAppConfirmationCodeValid) {
            session.setAuthenticatorAppFactorAuthPassed(true);
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
        return AuthenticatorAppConfirmationCodeAuthenticationSession.class.isAssignableFrom(authentication);
    }
}
