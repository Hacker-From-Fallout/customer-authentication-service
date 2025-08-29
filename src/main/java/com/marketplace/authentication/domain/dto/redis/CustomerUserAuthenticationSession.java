package com.marketplace.authentication.domain.dto.redis;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.marketplace.authentication.domain.entities.CustomerUser;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CustomerUserAuthenticationSession implements Authentication  {
    private CustomerUser principal;
    private boolean authenticated = false;
    private boolean emailFactorAuthPassed;
    private boolean phoneNumberFactorAuthPassed;
    private boolean authenticatorAppFactorAuthPassed;
    private String emailConfirmationCode;
    private String phoneNumberConfirmationCode;
    private String authenticatorAppConfirmationCode;
    private byte codeEntryAttemptsRemaining  = 5;
    private byte resendAttemptsRemaining = 5;

    public CustomerUserAuthenticationSession(CustomerUser customerUser) {
        this.principal = customerUser;

        this.emailFactorAuthPassed = 
            customerUser.isEmailFactorAuthEnabled() ? false : true;

        this.phoneNumberFactorAuthPassed = 
            customerUser.isPhoneNumberFactorAuthEnabled() ? false : true;

        this.authenticatorAppFactorAuthPassed =
            customerUser.isAuthenticatorAppFactorAuthEnabled() ? false : true;
    }

    public void decrementCodeEntryAttempts() {
            codeEntryAttemptsRemaining--;
    }

    public void decrementResendAttemptsRemaining() {
        resendAttemptsRemaining--;
    }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return principal.getAuthorities();
    }

    @Override
    @JsonIgnore
    public String getName() {
        return principal.getUsername();
    }

    @Override
    @JsonIgnore
    public Object getCredentials() {
        return principal.getHashPassword();
    }

    @Override
    @JsonIgnore
    public Object getDetails() {
        return null;
    }

    @Override
    public CustomerUser getPrincipal() {
        return principal;
    }

    @Override
    @JsonIgnore
    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setEmailFactorAuthPassed(boolean isPassed) {
        if (this.principal.isEmailFactorAuthEnabled()) {
            this.emailFactorAuthPassed = isPassed;
        }
    }
    
    public void setPhoneNumberFactorAuthPassed(boolean isPassed) {
        if (this.principal.isEmailFactorAuthEnabled()) {
            this.phoneNumberFactorAuthPassed = isPassed;
        }
    }

    public void setAuthenticatorAppFactorAuthPassed(boolean isPassed) {
        if (this.principal.isAuthenticatorAppFactorAuthEnabled()) {
            this.authenticatorAppFactorAuthPassed = isPassed;
        }
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (
            this.emailFactorAuthPassed && 
            this.phoneNumberFactorAuthPassed && 
            this.authenticatorAppFactorAuthPassed
        ) {
            this.authenticated = isAuthenticated;
        }
    }

    @JsonIgnore
    public boolean isMultiFactorAuthPassed() {
        return emailFactorAuthPassed && phoneNumberFactorAuthPassed && authenticatorAppFactorAuthPassed;
    }
}
