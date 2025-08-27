package com.marketplace.authentication.domain.dto.kafka;

public record EmailConfirmationCodeDto(
    String email,
    String code
) {}
