package dev.jarand.authprotectedrequests.authapi;

import java.security.PublicKey;

public interface AuthApiClient {

    PublicKey fetchPublicKey();

    String refreshToken(String refreshToken);
}
