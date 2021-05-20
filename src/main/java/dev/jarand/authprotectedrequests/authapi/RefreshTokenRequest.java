package dev.jarand.authprotectedrequests.authapi;

public class RefreshTokenRequest {

    private final String refreshToken;

    public RefreshTokenRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
