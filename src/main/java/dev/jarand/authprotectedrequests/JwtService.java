package dev.jarand.authprotectedrequests;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Optional;

@Service
public class JwtService {

    private final PublicKey publicKey;

    public JwtService(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public Optional<AccessTokenClaims> parseAccessToken(String accessToken) {
        Claims jwtClaims;
        try {
            jwtClaims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessToken).getBody();
        } catch (JwtException ex) {
            return Optional.empty();
        }
        if (!"ACCESS".equals(jwtClaims.get("type", String.class))) {
            return Optional.empty();
        }
        return Optional.of(new AccessTokenClaims(jwtClaims.getSubject(), jwtClaims.get("scope", String.class)));
    }
}
