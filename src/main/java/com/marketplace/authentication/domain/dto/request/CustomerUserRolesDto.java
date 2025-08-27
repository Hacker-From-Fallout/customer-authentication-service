package com.marketplace.authentication.domain.dto.request;

import java.util.EnumSet;

import com.marketplace.authentication.domain.authorities.CustomerUserRole;

import jakarta.validation.constraints.NotNull;

public record CustomerUserRolesDto(
    @NotNull(message = "Roles must be provided")
    EnumSet<CustomerUserRole> roles
) {}
