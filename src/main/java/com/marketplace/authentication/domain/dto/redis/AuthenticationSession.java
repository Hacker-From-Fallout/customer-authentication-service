package com.marketplace.authentication.domain.dto.redis;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.marketplace.authentication.domain.entities.CustomerUser;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationSession implements Authentication  {
    private CustomerUser principal;
    private boolean authenticated = false;
    private boolean emailFactorAuthPassed;
    private boolean phoneNumberFactorAuthPassed;
    protected boolean authenticatorAppFactorAuthPassed;
    private String emailConfirmationCode;
    private String phoneNumberConfirmationCode;
    private String authenticatorAppConfirmationCode;
    private byte codeEntryAttemptsRemaining  = 5;
    private byte resendAttemptsRemaining = 5;

    public AuthenticationSession(CustomerUser customerUser) {
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

    @JsonProperty("emailFactorAuthPassed")
    public boolean isEmailFactorAuthPassed() {
        return this.emailFactorAuthPassed;
    }

    @JsonProperty("phoneNumberFactorAuthPassed")
    public boolean isPhoneNumberFactorAuthPassed() {
        return this.phoneNumberFactorAuthPassed;
    }

    @JsonProperty("authenticatorAppFactorAuthPassed")
    public boolean isAuthenticatorAppFactorAuthPassed() {
        return this.authenticatorAppFactorAuthPassed;
    }

    @JsonIgnore
    public void setEmailFactorAuthPassed(boolean isPassed) {
        this.emailFactorAuthPassed = isPassed;
    }
    
    @JsonIgnore
    public void setPhoneNumberFactorAuthPassed(boolean isPassed) {
        this.phoneNumberFactorAuthPassed = isPassed;
    }

    @JsonIgnore
    public void setAuthenticatorAppFactorAuthPassed(boolean isPassed) {
        this.authenticatorAppFactorAuthPassed = isPassed;
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
