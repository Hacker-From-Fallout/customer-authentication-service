package com.marketplace.authentication.security;

import com.marketplace.authentication.domain.dto.redis.FailedLoginAttemptsSession;

public interface FailedLoginAttemptsSessionService {

    public FailedLoginAttemptsSession getSession(String sessionId);
    public void saveSession(String sessionId, FailedLoginAttemptsSession session);
    public void updateSession(String sessionId, FailedLoginAttemptsSession session);
    public void deleteSession(String sessionId);
}
