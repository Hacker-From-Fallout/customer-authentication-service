package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotNull;

public record AccountNonExpiredDto(
    @NotNull(message = "Account non-expired status must be specified")
    Boolean accountNonExpired
) {}
