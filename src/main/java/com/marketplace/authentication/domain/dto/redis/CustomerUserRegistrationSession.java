package com.marketplace.authentication.domain.dto.redis;

import java.util.EnumSet;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Builder
@AllArgsConstructor
@RequiredArgsConstructor
public class CustomerUserRegistrationSession {
    private String encryptedEmailConfirmationCodeSecret;
    private String encryptedPhoneNumberConfirmationCodeSecret;
    private String firstName;
    private String lastName;
    private String username;
    private String email;
    private String phoneNumber;
    private String hashPassword;
    private EnumSet<CustomerUserRole> roles;
    private EnumSet<CustomerUserAuthority> authorities;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;
    private boolean emailFactorAuthEnabled;
    private boolean phoneNumberFactorAuthEnabled;
    private boolean authenticatorAppFactorAuthEnabled;

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
}
