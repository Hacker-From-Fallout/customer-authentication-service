package com.marketplace.authentication.security;

import com.marketplace.authentication.domain.dto.redis.AuthenticationSession;

public interface AuthenticationSessionService {
    public AuthenticationSession getSession(String sessionId);
    public void saveSession(String sessionId, AuthenticationSession session);
    public void updateSession(String sessionId, AuthenticationSession session);
    public void deleteSession(String sessionId);
}
