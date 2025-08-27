package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotNull;

public record EnabledDto(
    @NotNull(message = "Enabled status must be specified")
    Boolean enabled
) {}
