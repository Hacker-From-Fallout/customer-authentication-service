package com.marketplace.authentication.security;

import java.time.Duration;

import com.marketplace.authentication.domain.dto.redis.FailedLoginAttemptsSession;

public interface FailedLoginAttemptsSessionService {

    public FailedLoginAttemptsSession getSession(String sessionId);
    public void saveSession(String sessionId, FailedLoginAttemptsSession session, Duration timeout);
    public void updateSession(String sessionId, FailedLoginAttemptsSession session, Duration timeout);
    public void deleteSession(String sessionId);
}
