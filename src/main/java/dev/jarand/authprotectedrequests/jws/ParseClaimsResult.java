package dev.jarand.authprotectedrequests.jws;

import io.jsonwebtoken.Claims;

import java.util.Optional;

public class ParseClaimsResult {

    private final ParseClaimsResultState state;
    private final Claims claims;

    public ParseClaimsResult(ParseClaimsResultState state, Claims claims) {
        this.state = state;
        this.claims = claims;
    }

    public ParseClaimsResultState getState() {
        return state;
    }

    public Optional<Claims> getClaims() {
        return Optional.ofNullable(claims);
    }
}
