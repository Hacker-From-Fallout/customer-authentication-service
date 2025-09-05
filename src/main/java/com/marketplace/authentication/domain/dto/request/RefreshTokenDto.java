package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenDto(
    @NotBlank(message = "refreshToken is required")
    String refreshToken
) {}
