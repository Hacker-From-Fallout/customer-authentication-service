package com.marketplace.authentication.security;

import java.time.Duration;

import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;

public interface CustomerUserRegistrationSessionService  {

    public CustomerUserRegistrationSession getSession(String sessionId);
    public CustomerUserRegistrationSession getSessionHash(String sessionId);
    public Object getFieldFromSession(String sessionId, String fieldName);
    public void saveSession(String sessionId, CustomerUserRegistrationSession session, Duration timeout);
    public void saveSessionAsHash(String sessionId, CustomerUserRegistrationSession session, Duration timeout);
    public void updateSession(String sessionId, CustomerUserRegistrationSession session, Duration timeout);
    public void updateFieldInSession(String sessionId, String fieldName, Object newValue);
    public void deleteSession(String sessionId);
}
