package dev.jarand.authprotectedrequests.cookie;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;

@Service
@ConditionalOnProperty(name = "authentication.mock.enabled", havingValue = "false", matchIfMissing = true)
class CookieServiceImpl implements CookieService {

    private final String name;
    private final boolean httpOnly;
    private final boolean secure;
    private final String domain;
    private final String path;
    private final int maxAge;

    public CookieServiceImpl(@Value("${authentication.cookie.name}") String name,
                             @Value("${authentication.cookie.httponly}") boolean httpOnly,
                             @Value("${authentication.cookie.secure}") boolean secure,
                             @Value("${authentication.cookie.domain}") String domain,
                             @Value("${authentication.cookie.path}") String path,
                             @Value("${authentication.cookie.maxAge}") int maxAge) {
        this.name = name;
        this.httpOnly = httpOnly;
        this.secure = secure;
        this.domain = domain;
        this.path = path;
        this.maxAge = maxAge;
    }

    @Override
    public Cookie createAccessTokenCookie(String accessToken) {
        final var cookie = new Cookie(name, accessToken);
        cookie.setHttpOnly(httpOnly);
        cookie.setSecure(secure);
        cookie.setDomain(domain);
        cookie.setPath(path);
        cookie.setMaxAge(maxAge);
        return cookie;
    }
}
