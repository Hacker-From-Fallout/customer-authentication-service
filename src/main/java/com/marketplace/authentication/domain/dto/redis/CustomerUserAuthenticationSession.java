package com.marketplace.authentication.domain.dto.redis;

import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CustomerUserAuthenticationSession implements UserDetails {
    private String username;
    private String hashPassword;
    private EnumSet<CustomerUserRole> roles;
    private EnumSet<CustomerUserAuthority> authorities;
    private boolean emailFactorAuthEnabled;
    private boolean phoneNumberFactorAuthEnabled;
    private boolean authenticatorAppFactorAuthEnabled;
    private String encryptedEmailConfirmationCodeSecret;
    private String encryptedPhoneNumberConfirmationCodeSecret;
    private String encryptedAuthenticatorAppConfirmationCodeSecret;

    @Builder.Default
    private byte codeEntryAttemptsRemaining  = 5;

    @Builder.Default
    private byte resendAttemptsRemaining = 5;

    public void decrementCodeEntryAttempts() {
            codeEntryAttemptsRemaining--;
    }

    public void decrementResendAttemptsRemaining() {
        resendAttemptsRemaining--;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = this.authorities.stream()
                    .map(CustomerUserAuthority::name)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

        authorities.addAll(this.roles.stream()
                    .map(CustomerUserRole::name)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList()));
    
        return authorities;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return hashPassword;
    }
}
