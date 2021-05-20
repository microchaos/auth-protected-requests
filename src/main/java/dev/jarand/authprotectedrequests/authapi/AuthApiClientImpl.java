package dev.jarand.authprotectedrequests.authapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@ConditionalOnProperty(name = "authentication.mock.enabled", havingValue = "false", matchIfMissing = true)
public class AuthApiClientImpl implements AuthApiClient {

    private static final Logger logger = LoggerFactory.getLogger(AuthApiClientImpl.class);

    private final String publicKeyEndpoint;
    private final String refreshTokenEndpoint;
    private final RestTemplate authApiRestTemplate;

    public AuthApiClientImpl(@Value("${authentication.api.endpoint.public-key}") String publicKeyEndpoint,
                             @Value("${authentication.api.endpoint.refresh-token}") String refreshTokenEndpoint,
                             RestTemplate authApiRestTemplate) {
        this.publicKeyEndpoint = publicKeyEndpoint;
        this.refreshTokenEndpoint = refreshTokenEndpoint;
        this.authApiRestTemplate = authApiRestTemplate;
    }

    @Override
    public PublicKey fetchPublicKey() {
        final ResponseEntity<KeyResource> response = authApiRestTemplate.getForEntity(publicKeyEndpoint, KeyResource.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Received invalid status " + response.getStatusCodeValue() + " from auth-api");
        }
        if (response.getBody() == null) {
            throw new IllegalStateException("Received empty body from auth-api");
        }
        final byte[] keyBytes = Base64.getDecoder().decode(response.getBody().getKey());
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Throwable throwable) {
            throw new RuntimeException(throwable);
        }
    }

    @Override
    public String refreshToken(String refreshToken) {
        try {
            logger.debug("Sending POST to refresh token");
            final RefreshTokenResponse response = authApiRestTemplate.postForObject(refreshTokenEndpoint, new RefreshTokenRequest(refreshToken), RefreshTokenResponse.class);
            if (response == null) {
                logger.debug("Response from auth-api was null. Returning null.");
                return null;
            }
            return response.getAccessToken();
        } catch (HttpClientErrorException ex) {
            logger.debug("Response from auth-api was " + ex.getRawStatusCode() + ". Returning null.");
            return null;
        }
    }
}
