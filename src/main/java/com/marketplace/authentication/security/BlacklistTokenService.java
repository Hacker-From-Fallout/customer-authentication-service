package com.marketplace.authentication.security;

public interface BlacklistTokenService {
    public String getToken(String tokenId);
    public void saveToken(String tokenId);
    public void updateToken(String tokenId);
    public void deleteToken(String tokenId);
}
