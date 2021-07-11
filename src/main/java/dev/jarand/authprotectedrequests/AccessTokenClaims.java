package dev.jarand.authprotectedrequests;

import java.util.Optional;

public class AccessTokenClaims {

    private final String subject;
    private final String scope;

    public AccessTokenClaims(String subject, String scope) {
        this.subject = subject;
        this.scope = scope;
    }

    public String getSubject() {
        return subject;
    }

    public Optional<String> getScope() {
        return Optional.ofNullable(scope);
    }
}
