package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ConfirmationRegistrarionCodesDto(

    @NotBlank(message = "Email confirmation code name is required")
    String emailConfirmationCode,

    @NotBlank(message = "Phone number confirmation code confirmation code name is required")
    String phoneNumberConfirmationCode
) {}
