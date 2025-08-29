package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ConfirmationCodeDto(

    @NotBlank(message = "Confirmation code is required")
    String code
) {}
