package com.marketplace.authentication.security;

import com.marketplace.authentication.domain.dto.redis.CustomerUserAuthenticationSession;

public interface CustomerUserAuthenticationSessionService {
    public CustomerUserAuthenticationSession getSession(String sessionId);
    public void saveSession(String sessionId, CustomerUserAuthenticationSession session);
    public void updateSession(String sessionId, CustomerUserAuthenticationSession session);
    public void deleteSession(String sessionId);
}
