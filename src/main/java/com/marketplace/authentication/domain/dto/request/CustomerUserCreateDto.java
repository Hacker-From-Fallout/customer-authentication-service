package com.marketplace.authentication.domain.dto.request;

import java.util.EnumSet;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CustomerUserCreateDto(
    @NotBlank(message = "First name is required")
    @Pattern(regexp = "^[A-Za-z]+$", message = "First name must contain only letters")
    @Size(max = 50, message = "First name must be at most 50 characters")
    String firstName,

    @NotBlank(message = "Last name is required")
    @Pattern(regexp = "^[A-Za-z]+$", message = "Last name must contain only letters")
    @Size(max = 50, message = "Last name must be at most 50 characters")
    String lastName,

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    String username,

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    String email,

    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$", message = "Phone number must be in international format with country code")
    String phoneNumber,

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
        message = "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character"
    )
    String password,

    @NotNull(message = "Roles must be provided")
    EnumSet<CustomerUserRole> roles,

    @NotNull(message = "Authorities must be provided")
    EnumSet<CustomerUserAuthority> authorities,

    @NotNull(message = "Account non-expired status must be specified")
    Boolean accountNonExpired,

    @NotNull(message = "Account non-locked status must be specified")
    Boolean accountNonLocked,

    @NotNull(message = "Credentials non-expired status must be specified")
    Boolean credentialsNonExpired,

    @NotNull(message = "Enabled status must be specified")
    Boolean enabled,

    @NotNull(message = "Email factor authentication enabled status must be specified")
    Boolean emailFactorAuthEnabled,

    @NotNull(message = "Phone factor authentication enabled status must be specified")
    Boolean phoneNumberFactorAuthEnabled,

    @NotNull(message = "Authenticator application factor authentication enabled status must be specified")
    Boolean authenticatorAppFactorAuthEnabled
) {} 
