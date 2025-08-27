package com.marketplace.authentication.domain.dto.kafka;

public record CustomerProfileCreateDto(
    Long id,
    String firstName,
    String lastName,
    String username,
    String email,
    String phoneNumber
) {}
