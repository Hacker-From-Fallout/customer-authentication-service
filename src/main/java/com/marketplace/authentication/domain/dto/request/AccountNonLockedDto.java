package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotNull;

public record AccountNonLockedDto(
    @NotNull(message = "Account non-locked status must be specified")
    Boolean accountNonLocked
) {}
