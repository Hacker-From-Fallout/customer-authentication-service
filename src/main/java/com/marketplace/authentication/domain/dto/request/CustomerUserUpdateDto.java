package com.marketplace.authentication.domain.dto.request;

import java.time.LocalDateTime;
import java.util.EnumSet;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CustomerUserUpdateDto(
    @Pattern(regexp = "^[A-Za-z]+$", message = "First name must contain only letters")
    @Size(max = 50, message = "First name must be at most 50 characters")
    String firstName,

    @Pattern(regexp = "^[A-Za-z]+$", message = "Last name must contain only letters")
    @Size(max = 50, message = "Last name must be at most 50 characters")
    String lastName,

    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    String username,

    @Email(message = "Email should be valid")
    String email,

    @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$", message = "Phone number must be in international format with country code")
    String phoneNumber,

    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
        message = "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character"
    )
    String password,

    EnumSet<CustomerUserRole> roles,
    EnumSet<CustomerUserAuthority> authorities,

    Boolean accountNonExpired,
    Boolean accountNonLocked,
    Boolean credentialsNonExpired,
    Boolean enabled,
    Boolean emailFactorAuthEnabled,
    Boolean phoneNumberFactorAuthEnabled,
    Boolean authenticatorAppFactorAuthEnabled,
    
    LocalDateTime lastLoginDate
) {}
