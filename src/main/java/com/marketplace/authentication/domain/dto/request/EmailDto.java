package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;

public record EmailDto(
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    String email
) {}
