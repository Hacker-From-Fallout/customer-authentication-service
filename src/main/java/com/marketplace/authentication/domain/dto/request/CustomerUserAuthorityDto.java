package com.marketplace.authentication.domain.dto.request;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;

import jakarta.validation.constraints.NotNull;

public record CustomerUserAuthorityDto(
    @NotNull(message = "Authority must be provided")
    CustomerUserAuthority authority
) {}
