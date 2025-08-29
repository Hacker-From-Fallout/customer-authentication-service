package com.marketplace.authentication.domain.dto.request;

public record CustomerUserAuthenticationDto(
    String login,
    String password
) {}
