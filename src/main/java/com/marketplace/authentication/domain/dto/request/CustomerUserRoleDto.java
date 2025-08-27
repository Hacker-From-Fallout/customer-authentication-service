package com.marketplace.authentication.domain.dto.request;

import com.marketplace.authentication.domain.authorities.CustomerUserRole;

import jakarta.validation.constraints.NotNull;

public record CustomerUserRoleDto(
    @NotNull(message = "Role must be provided")
    CustomerUserRole role
) {}
