package com.example.identity_service.config;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.JwtUser;
import com.example.identity_service.service.authentication.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Authenticates a request from its "Authorization: Bearer {token}" header.
 *
 * With a valid token the user is placed in the SecurityContext, built from the token alone (no database
 * access). The filter never rejects a request itself. A missing or bad token only leaves the request
 * unauthenticated; whether that matters is decided later by the authorization rules, and
 * {@link JwtAuthenticationEntryPoint} writes the 401 when it does. So a client holding an expired token
 * can still call public endpoints such as register and login.
 *
 * Not annotated with @Component on purpose: Spring Boot would also register every Filter bean in the
 * servlet container, outside the security chain. SecurityConfig creates it and adds it to the chain.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /** Request attribute holding the {@link ErrorCode} of a rejected token, read by the entry point. */
    public static final String TOKEN_ERROR_ATTRIBUTE = JwtAuthenticationFilter.class.getName() + ".TOKEN_ERROR";

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        // The scheme name is case-insensitive (RFC 7235). Other schemes, e.g. Basic, are not ours to judge.
        if (header != null && header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            authenticate(header.substring(BEARER_PREFIX.length()).trim(), request);
        }

        filterChain.doFilter(request, response);
    }

    private void authenticate(String token, HttpServletRequest request) {
        try {
            JwtUser user = jwtService.getUserFromToken(token);

            List<SimpleGrantedAuthority> authorities = user.authorities().stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList();

            // The principal is the JwtUser: the id of the user and their authorities, nothing else.
            UsernamePasswordAuthenticationToken authentication =
                    UsernamePasswordAuthenticationToken.authenticated(user, null, authorities);

            // A fresh context, not getContext().setAuthentication(...), so no other thread shares it.
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
        } catch (GeneralException e) {
            if (e.getErrorCode() != ErrorCode.INVALID_TOKEN && e.getErrorCode() != ErrorCode.TOKEN_EXPIRED) {
                // Not the client's fault (e.g. our secret is misconfigured): do not hide it as a 401.
                throw e;
            }
            SecurityContextHolder.clearContext();
            request.setAttribute(TOKEN_ERROR_ATTRIBUTE, e.getErrorCode());
        }
    }
}
