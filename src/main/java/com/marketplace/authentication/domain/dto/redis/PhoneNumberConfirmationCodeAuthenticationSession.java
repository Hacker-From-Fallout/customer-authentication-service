package com.marketplace.authentication.domain.dto.redis;

public class PhoneNumberConfirmationCodeAuthenticationSession extends AuthenticationSession {

    public PhoneNumberConfirmationCodeAuthenticationSession(AuthenticationSession session) {
        if (session != null) {
            this.setPrincipal(session.getPrincipal());
            this.setAuthenticated(session.isAuthenticated());
            this.setEmailFactorAuthPassed(session.isEmailFactorAuthPassed());
            this.setPhoneNumberFactorAuthPassed(session.isPhoneNumberFactorAuthPassed());
            this.setAuthenticatorAppFactorAuthPassed(session.isAuthenticatorAppFactorAuthPassed());
            this.setEmailConfirmationCode(session.getEmailConfirmationCode());
            this.setPhoneNumberConfirmationCode(session.getPhoneNumberConfirmationCode());
            this.setAuthenticatorAppConfirmationCode(session.getAuthenticatorAppConfirmationCode());
            this.setCodeEntryAttemptsRemaining(session.getCodeEntryAttemptsRemaining());
            this.setResendAttemptsRemaining(session.getResendAttemptsRemaining());
        }
    }
}
