package com.marketplace.authentication.domain.dto.request;

public record CustomerUserFilterDto(
    String username,
    String email,
    String phoneNumber
) {}
