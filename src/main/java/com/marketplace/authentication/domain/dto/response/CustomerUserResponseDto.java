package com.marketplace.authentication.domain.dto.response;

import java.time.LocalDateTime;
import java.util.EnumSet;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;
import com.marketplace.authentication.domain.entities.CustomerUser;

public record CustomerUserResponseDto(
    Long id,
    String username,
    String email,
    String phoneNumber,
    EnumSet<CustomerUserRole> roles,
    EnumSet<CustomerUserAuthority> authorities,
    boolean accountNonExpired,
    boolean accountNonLocked,
    boolean credentialsNonExpired,
    boolean enabled,
    boolean emailFactorAuthEnabled,
    boolean phoneNumberFactorAuthEnabled,
    boolean authenticatorAppFactorAuthEnabled,
    LocalDateTime registrationDate,
    LocalDateTime lastLoginDate
) {
    public static CustomerUserResponseDto from(CustomerUser customerUser) {
        return new CustomerUserResponseDto(
            customerUser.getId(),
            customerUser.getUsername(),
            customerUser.getEmail(),
            customerUser.getPhoneNumber(),
            customerUser.getRoles().isEmpty() ? EnumSet.noneOf(CustomerUserRole.class) : EnumSet.copyOf(customerUser.getRoles()),
            customerUser.getAuthorities().isEmpty() ? EnumSet.noneOf(CustomerUserAuthority.class) : EnumSet.copyOf(customerUser.getAuthoritiesSet()),
            customerUser.isAccountNonExpired(),
            customerUser.isAccountNonLocked(),
            customerUser.isCredentialsNonExpired(),
            customerUser.isEnabled(),
            customerUser.isEmailFactorAuthEnabled(),
            customerUser.isPhoneNumberFactorAuthEnabled(),
            customerUser.isAuthenticatorAppFactorAuthEnabled(),
            customerUser.getRegistrationDate(),
            customerUser.getLastLoginDate()
        );
    }
}
