package dev.jarand.authprotectedrequests.cookie

import javax.servlet.http.Cookie

interface CookieService {
    fun createAccessTokenCookie(accessToken: String): Cookie
}
