package dev.jarand.authprotectedrequests

import dev.jarand.authapi.jws.domain.ParseClaimsResultState
import dev.jarand.authprotectedrequests.jws.JwsService
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import java.util.*
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.streams.toList

class BearerAuthenticationFilter(private val jwsService: JwsService) : Filter {

    override fun doFilter(servletRequest: ServletRequest, servletResponse: ServletResponse, chain: FilterChain) {
        val request = servletRequest as HttpServletRequest
        val response = servletResponse as HttpServletResponse

        if (request.cookies == null || request.cookies.isEmpty()) {
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val tokenCookie = Arrays.stream(request.cookies).filter { it.name == "token" }.findFirst().orElse(null)
        if (tokenCookie == null) {
            response.sendError(HttpStatus.UNAUTHORIZED.value())
            return
        }

        val encodedJws = tokenCookie.value

        val result = jwsService.parseClaims(encodedJws)
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
