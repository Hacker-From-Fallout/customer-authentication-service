package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ConfirmationRegistrarionCodesDto(

    @NotBlank(message = "Email confirmation code is required")
    String emailConfirmationCode,

    @NotBlank(message = "Phone number confirmation code is required")
    String phoneNumberConfirmationCode
) {}
