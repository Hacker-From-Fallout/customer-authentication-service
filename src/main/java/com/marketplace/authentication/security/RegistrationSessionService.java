package com.marketplace.authentication.security;

import com.marketplace.authentication.domain.dto.redis.RegistrationSession;

public interface RegistrationSessionService  {
    public RegistrationSession getSession(String sessionId);
    public void saveSession(String sessionId, RegistrationSession session);
    public void updateSession(String sessionId, RegistrationSession session);
    public void deleteSession(String sessionId);
}
