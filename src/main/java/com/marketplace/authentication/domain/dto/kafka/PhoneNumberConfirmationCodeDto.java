package com.marketplace.authentication.domain.dto.kafka;

public record PhoneNumberConfirmationCodeDto(
    String phoneNumber,
    String code
) {}