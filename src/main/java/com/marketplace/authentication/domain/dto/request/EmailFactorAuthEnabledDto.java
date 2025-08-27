package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotNull;

public record EmailFactorAuthEnabledDto(
    @NotNull(message = "Enabled non-expired status must be specified")
    Boolean enabled
) {}
