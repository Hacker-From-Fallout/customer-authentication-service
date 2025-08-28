package com.marketplace.authentication.security;

import java.time.Duration;

import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;

public interface CustomerUserRegistrationSessionService  {

    public CustomerUserRegistrationSession getSession(String sessionId);
    public void saveSession(String sessionId, CustomerUserRegistrationSession session, Duration timeout);
    public void updateSession(String sessionId, CustomerUserRegistrationSession session, Duration timeout);
    public void deleteSession(String sessionId);
}
