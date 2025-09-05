package com.marketplace.authentication.security;

import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;

public interface CustomerUserRegistrationSessionService  {

    public CustomerUserRegistrationSession getSession(String sessionId);
    public void saveSession(String sessionId, CustomerUserRegistrationSession session);
    public void updateSession(String sessionId, CustomerUserRegistrationSession session);
    public void deleteSession(String sessionId);
}
