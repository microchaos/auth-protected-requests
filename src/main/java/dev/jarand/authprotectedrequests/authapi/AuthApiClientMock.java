package dev.jarand.authprotectedrequests.authapi;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.security.PublicKey;

@Service
@ConditionalOnProperty(name = "authentication.mock.enabled", havingValue = "true")
public class AuthApiClientMock implements AuthApiClient {

    @Override
    public PublicKey fetchPublicKey() {
        throw new IllegalStateException("Not implemented");
    }

    @Override
    public String refreshToken(String refreshToken) {
        throw new IllegalStateException("Not implemented");
    }
}
