package dev.jarand.authprotectedrequests

import dev.jarand.authprotectedrequests.authapi.AuthApiClient
import dev.jarand.authprotectedrequests.jws.JwsService
import dev.jarand.authprotectedrequests.jws.ParseClaimsResultState
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
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val accessTokenCookie = Arrays.stream(request.cookies).filter { it.name == "access_token" }.findFirst().orElse(null)

        if (accessTokenCookie == null) {
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val accessToken = accessTokenCookie.value

        var result = jwsService.parseClaims(accessToken)
        if (result.state == ParseClaimsResultState.EXPIRED) {
            val refreshTokenCookie = Arrays.stream(request.cookies).filter { it.name == "refresh_token" }.findFirst().orElse(null)
            val refreshToken = refreshTokenCookie.value
            val refreshedAccessToken = authApiClient.refreshToken(refreshToken)
            refreshedAccessToken?.let {
                result = jwsService.parseClaims(it)
                val cookie = Cookie("access_token", it)
                cookie.isHttpOnly = accessTokenCookie.isHttpOnly
                cookie.secure = accessTokenCookie.secure
                cookie.domain = accessTokenCookie.domain
                cookie.path = accessTokenCookie.path
                cookie.maxAge = accessTokenCookie.maxAge
                response.addCookie(cookie)
            }
        }
        if (result.state != ParseClaimsResultState.SUCCESS) {
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
}
