package com.marketplace.authentication.domain.dto.request;

import java.util.EnumSet;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;

import jakarta.validation.constraints.NotNull;

public record CustomerUserAuthoritiesDto(
    @NotNull(message = "Authorities must be provided")
    EnumSet<CustomerUserAuthority> authorities
) {}
