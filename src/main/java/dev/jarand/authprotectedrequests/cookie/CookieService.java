package dev.jarand.authprotectedrequests.cookie;

import javax.servlet.http.Cookie;

public interface CookieService {

    Cookie createAccessTokenCookie(String accessToken);
}
