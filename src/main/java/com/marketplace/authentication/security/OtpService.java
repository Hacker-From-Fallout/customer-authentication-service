package com.marketplace.authentication.security;

public interface OtpService {
    public String generateSecret();
    public String generateCurrentCode(String base64Secret);
    public boolean verifyCode(String code, String base64Secret);
}
