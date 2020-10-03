package dev.jarand.authprotectedrequests

import dev.jarand.authprotectedrequests.authapi.AuthApiClient
import dev.jarand.authprotectedrequests.jws.JwsService
import dev.jarand.authprotectedrequests.jws.ParseClaimsResultState
import io.jsonwebtoken.Claims
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import java.util.*
import java.util.stream.Collectors
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
            logger.debug("No cookies sent with request. Returning 401.")
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val tokenCookies = Arrays.stream(request.cookies)
                .filter { it.name == "access_token" || it.name == "refresh_token" }
                .collect(Collectors.toUnmodifiableList())
        logger.debug("Found ${tokenCookies.size} token cookies.")

        for (tokenCookie in tokenCookies) {
            if (tokenCookie.name == "access_token") {
                logger.debug("Processing access_token.")
                val result = jwsService.parseClaims(tokenCookie.value)
                if (result.state == ParseClaimsResultState.SUCCESS && result.claims != null) {
                    logger.debug("Successfully parsed access_token. Setting security context.")
                    setSecurityContext(result.claims)
                } else if (result.state != ParseClaimsResultState.EXPIRED) {
                    logger.debug("Parse failed with state ${result.state}. Returning 401.")
                    response.sendError(HttpStatus.UNAUTHORIZED.value())
                    return
                }
            } else if (tokenCookie.name == "refresh_token") {
                logger.debug("Processing refresh_token.")
                val accessToken = authApiClient.refreshToken(tokenCookie.value)
                if (accessToken == null) {
                    logger.debug("No access_token returned when trying to refresh token. Returning 401.")
                    response.sendError(HttpStatus.UNAUTHORIZED.value())
                    return
                }
                val result = jwsService.parseClaims(tokenCookie.value)
                if (result.state == ParseClaimsResultState.SUCCESS && result.claims != null) {
                    logger.debug("Successfully parsed access_token after refreshing. Adding new access token to cookie.")
                    response.addCookie(createCookie(accessToken, tokenCookie))
                    logger.debug("Successfully added access_token to cookie. Setting security context.")
                    setSecurityContext(result.claims)
                } else if (result.state != ParseClaimsResultState.EXPIRED) {
                    logger.debug("Parse after refreshing failed with state ${result.state}. Returning 401.")
                    response.sendError(HttpStatus.UNAUTHORIZED.value())
                    return
                }
            }
        }

        chain.doFilter(request, response)
    }

    private fun setSecurityContext(claims: Claims) {
        val authorities = claims.get("scope", String::class.java).split(" ").stream().map { SimpleGrantedAuthority("ROLE_$it") }.toList()
        val authentication = UsernamePasswordAuthenticationToken(claims.subject, null, authorities)

        val securityContext = SecurityContextHolder.getContext()
        securityContext.authentication = authentication
    }

    private fun createCookie(accessToken: String, refreshTokenCookie: Cookie): Cookie {
        val cookie = Cookie("access_token", accessToken)
        cookie.isHttpOnly = refreshTokenCookie.isHttpOnly
        cookie.secure = refreshTokenCookie.secure
        cookie.domain = refreshTokenCookie.domain
        cookie.path = refreshTokenCookie.path
        cookie.maxAge = 3600
        return cookie
    }

    companion object {
        private val logger = LoggerFactory.getLogger(BearerAuthenticationFilter::class.java)
    }
}
