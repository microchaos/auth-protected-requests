package dev.jarand.authprotectedrequests;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class AuthApiClient {

    private final RestTemplate authApiRestTemplate;

    public AuthApiClient(RestTemplate authApiRestTemplate) {
        this.authApiRestTemplate = authApiRestTemplate;
    }

    public PublicKey fetchPublicKey() {
        final ResponseEntity<String> response = authApiRestTemplate.getForEntity("/key/public", String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Received invalid status " + response.getStatusCodeValue() + " from auth-api");
        }
        if (response.getBody() == null) {
            throw new IllegalStateException("Received empty body from auth-api");
        }
        final byte[] keyBytes = Base64.getDecoder().decode(response.getBody());
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Throwable throwable) {
            throw new RuntimeException(throwable);
        }
    }
}
