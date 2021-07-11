package dev.jarand.authprotectedrequests;

import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TokenService {

    private final JwtService jwtService;

    public TokenService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    public Optional<AccessTokenClaims> parseAccessToken(String accessToken) {
        return jwtService.parseAccessToken(accessToken);
    }
}
