package dev.jarand.authprotectedrequests

import dev.jarand.authprotectedrequests.authapi.AuthApiClient
import dev.jarand.authprotectedrequests.jws.JwsService
import dev.jarand.authprotectedrequests.jws.ParseClaimsResultState
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import java.util.*
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.streams.toList

class BearerAuthenticationFilter(private val jwsService: JwsService, private val authApiClient: AuthApiClient) : Filter {

    override fun doFilter(servletRequest: ServletRequest, servletResponse: ServletResponse, chain: FilterChain) {
        val request = servletRequest as HttpServletRequest
        val response = servletResponse as HttpServletResponse

        if (request.cookies == null || request.cookies.isEmpty()) {
            logger.debug("No cookies. Returning 401.")
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val accessTokenCookie = Arrays.stream(request.cookies).filter { it.name == "access_token" }.findFirst().orElse(null)
        val refreshTokenCookie = Arrays.stream(request.cookies).filter { it.name == "refresh_token" }.findFirst().orElse(null)

        if (accessTokenCookie == null && refreshTokenCookie == null) {
            logger.debug("No access or refresh token in cookies. Returning 401.")
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        var accessToken: String? = null
        if (accessTokenCookie != null) {
            accessToken = accessTokenCookie.value
            var result = jwsService.parseClaims(accessToken)
            if (result.state == ParseClaimsResultState.EXPIRED && refreshTokenCookie != null) {
                val refreshedAccessToken = authApiClient.refreshToken(refreshTokenCookie.value)
                refreshedAccessToken?.let {
                    result = jwsService.parseClaims(it)
                    response.addCookie(createCookie(it, accessTokenCookie))
                    accessToken = it
                }
            }
        }

        if (accessToken == null) {
            logger.debug("No access token potentially refreshing expired token. Returning 401.")
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val result = jwsService.parseClaims(accessToken!!)
        if (result.state != ParseClaimsResultState.SUCCESS) {
            logger.debug("Could not parse access token. State: ${result.state}. Returning 401.")
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val claims = result.claims!!
        val authorities = claims.get("scope", String::class.java).split(" ").stream().map { SimpleGrantedAuthority("ROLE_$it") }.toList()
        val authentication = UsernamePasswordAuthenticationToken(claims.subject, null, authorities)

        val securityContext = SecurityContextHolder.getContext()
        securityContext.authentication = authentication

        chain.doFilter(request, response)
    }

    private fun createCookie(accessToken: String, oldAccessTokenCookie: Cookie): Cookie {
        val cookie = Cookie("access_token", accessToken)
        cookie.isHttpOnly = oldAccessTokenCookie.isHttpOnly
        cookie.secure = oldAccessTokenCookie.secure
        cookie.domain = oldAccessTokenCookie.domain
        cookie.path = oldAccessTokenCookie.path
        cookie.maxAge = oldAccessTokenCookie.maxAge
        return cookie
    }

    companion object {
        private val logger = LoggerFactory.getLogger(BearerAuthenticationFilter::class.java)
    }
}
