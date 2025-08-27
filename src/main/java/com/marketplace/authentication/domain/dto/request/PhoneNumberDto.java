package com.marketplace.authentication.domain.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record PhoneNumberDto(
    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$", message = "Phone number must be in international format with country code")
    String phoneNumber
) {}
