package dev.jarand.authprotectedrequests.jws;

import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "authentication.mock.enabled", havingValue = "true")
public class JwsServiceMock implements JwsService {

    private final String scope;

    public JwsServiceMock(@Value("${authentication.mock.scope}") String scope) {
        this.scope = scope;
    }

    @Override
    public ParseClaimsResult parseClaims(String encodedJws) {
        final var claims = new DefaultClaims();
        claims.setSubject("mock");
        claims.put("scope", scope);
        return new ParseClaimsResult(ParseClaimsResultState.SUCCESS, claims);
    }
}
