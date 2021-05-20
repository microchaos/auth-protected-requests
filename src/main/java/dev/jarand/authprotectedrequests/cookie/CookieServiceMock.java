package dev.jarand.authprotectedrequests.cookie;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;

@Service
@ConditionalOnProperty(name = "authentication.mock.enabled", havingValue = "true")
public class CookieServiceMock implements CookieService {

    @Override
    public Cookie createAccessTokenCookie(String accessToken) {
        throw new IllegalStateException("Not implemented");
    }
}
