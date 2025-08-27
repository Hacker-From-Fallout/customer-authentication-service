package com.marketplace.authentication.domain.dto.request;

import java.time.LocalDateTime;

import jakarta.validation.constraints.NotNull;

public record LastLoginDateDto(
    @NotNull(message = "Last login date must be provided")
    LocalDateTime lastLoginDate
) {}
