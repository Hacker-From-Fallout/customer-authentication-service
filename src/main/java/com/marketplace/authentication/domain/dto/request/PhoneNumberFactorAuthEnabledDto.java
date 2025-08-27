package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotNull;

public record PhoneNumberFactorAuthEnabledDto(
    @NotNull(message = "Enabled non-expired status must be specified")
    Boolean enabled
) {}
