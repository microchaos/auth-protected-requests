package dev.jarand.authprotectedrequests;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BearerAuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(BearerAuthenticationFilter.class);

    private final TokenService tokenService;

    public BearerAuthenticationFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        final var request = (HttpServletRequest) servletRequest;
        final var response = (HttpServletResponse) servletResponse;
        final var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null) {
            response.sendError(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        final var accessToken = authorizationHeader.replace("Bearer", "").replace("bearer", "");
        final var optionalClaims = tokenService.parseAccessToken(accessToken);
        if (optionalClaims.isEmpty()) {
            response.sendError(HttpStatus.UNAUTHORIZED.value());
            return;
        }
        final var claims = optionalClaims.get();
        final var clientId = claims.getSubject();
        final var authorities = new ArrayList<SimpleGrantedAuthority>();
        final var optionalScopeClaim = claims.getScope();
        if (optionalScopeClaim.isPresent()) {
            final var scopes = List.of(optionalScopeClaim.get().split(" "));
            authorities.addAll(scopes.stream().map(SimpleGrantedAuthority::new).toList());
        }
        final var authentication = new UsernamePasswordAuthenticationToken(clientId, null, authorities);
        final var securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);
        logger.info("Successfully authenticated client with clientId: {} and {} scopes", clientId, authorities.size());

        chain.doFilter(request, response);
    }
}
