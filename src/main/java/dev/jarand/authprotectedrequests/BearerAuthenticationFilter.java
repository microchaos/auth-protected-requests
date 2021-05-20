package dev.jarand.authprotectedrequests;

import dev.jarand.authprotectedrequests.authapi.AuthApiClient;
import dev.jarand.authprotectedrequests.cookie.CookieService;
import dev.jarand.authprotectedrequests.jws.JwsService;
import dev.jarand.authprotectedrequests.jws.ParseClaimsResultState;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BearerAuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(BearerAuthenticationFilter.class);

    private final JwsService jwsService;
    private final CookieService cookieService;
    private final AuthApiClient authApiClient;

    public BearerAuthenticationFilter(JwsService jwsService, CookieService cookieService, AuthApiClient authApiClient) {
        this.jwsService = jwsService;
        this.cookieService = cookieService;
        this.authApiClient = authApiClient;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        final var request = (HttpServletRequest) servletRequest;
        final var response = (HttpServletResponse) servletResponse;

        if (request.getCookies() == null || request.getCookies().length == 0) {
            logger.debug("No cookies sent with request. Returning 401.");
            response.sendError(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        final var accessTokenCookie = Arrays.stream(request.getCookies()).filter(cookie -> "access_token".equals(cookie.getName())).findFirst().orElse(null);
        final var refreshTokenCookie = Arrays.stream(request.getCookies()).filter(cookie -> "refresh_token".equals(cookie.getName())).findFirst().orElse(null);
        final var tokenCookies = List.of(accessTokenCookie, refreshTokenCookie);
        logger.debug("Found {} token cookies.", tokenCookies.size());

        var securityContextSet = false;

        for (final var tokenCookie : tokenCookies) {
            if ("access_token".equals(tokenCookie.getName())) {
                logger.debug("Processing access_token.");
                final var result = jwsService.parseClaims(tokenCookie.getValue());
                if (result.getState() == ParseClaimsResultState.SUCCESS && result.getClaims().isPresent()) {
                    logger.debug("Successfully parsed access_token. Setting security context.");
                    setSecurityContext(result.getClaims().get());
                    securityContextSet = true;
                } else if (result.getState() != ParseClaimsResultState.EXPIRED) {
                    logger.debug("Parse failed with state {}. Returning 401.", result.getState());
                    response.sendError(HttpStatus.UNAUTHORIZED.value());
                    return;
                }
            } else if ("refresh_token".equals(tokenCookie.getName())) {
                logger.debug("Processing refresh_token.");
                if (!securityContextSet) {
                    final var accessToken = authApiClient.refreshToken(tokenCookie.getValue());
                    if (accessToken == null) {
                        logger.debug("No access_token returned when trying to refresh token. Returning 401.");
                        response.sendError(HttpStatus.UNAUTHORIZED.value());
                        return;
                    }
                    final var result = jwsService.parseClaims(tokenCookie.getValue());
                    if (result.getState() == ParseClaimsResultState.SUCCESS && result.getClaims().isPresent()) {
                        logger.debug("Successfully parsed access_token after refreshing. Adding new access token to cookie.");
                        response.addCookie(cookieService.createAccessTokenCookie(accessToken));
                        logger.debug("Successfully added access_token to cookie. Setting security context.");
                        setSecurityContext(result.getClaims().get());
                    } else if (result.getState() != ParseClaimsResultState.EXPIRED) {
                        logger.debug("Parse after refreshing failed with state {}. Returning 401.", result.getState());
                        response.sendError(HttpStatus.UNAUTHORIZED.value());
                        return;
                    }
                } else {
                    logger.debug("Security context has been set. Skipping refresh_token processing.");
                }
            }
        }

        chain.doFilter(request, response);
    }

    private void setSecurityContext(Claims claims) {
        final var authorities = Arrays.stream(claims.get("scope", String.class).split(" "))
                .map(authority -> new SimpleGrantedAuthority("ROLE_" + authority))
                .collect(Collectors.toUnmodifiableList());
        final var authentication = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);

        final var securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);
    }
}
