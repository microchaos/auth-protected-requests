package dev.jarand.authprotectedrequests.cookie

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import javax.servlet.http.Cookie

@Service
@ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "false", matchIfMissing = true)
class CookieService(@Value("authentication.cookie.name") private val name: String,
                    @Value("authentication.cookie.http-only") private val httpOnly: Boolean,
                    @Value("authentication.cookie.secure") private val secure: Boolean,
                    @Value("authentication.cookie.domain") private val domain: String,
                    @Value("authentication.cookie.path") private val path: String,
                    @Value("authentication.cookie.max-age") private val maxAge: Int) {
    fun createAccessTokenCookie(accessToken: String): Cookie {
        val cookie = Cookie(name, accessToken)
        cookie.isHttpOnly = httpOnly
        cookie.secure = secure
        cookie.domain = domain
        cookie.path = path
        cookie.maxAge = maxAge
        return cookie
    }
}
