package com.example.identity_service.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.JwtUser;
import com.example.identity_service.service.authentication.JwtService;

class JwtAuthenticationFilterTest {

    private final JwtService jwtService = mock(JwtService.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtService);

    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final MockFilterChain chain = new MockFilterChain();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validTokenAuthenticatesTheUserFromTheClaims() throws Exception {
        UUID userId = UUID.randomUUID();
        JwtUser jwtUser = new JwtUser(userId, List.of("ROLE_USER", "ROLE_ADMIN"));
        when(jwtService.getUserFromToken("good-token")).thenReturn(jwtUser);
        request.addHeader("Authorization", "Bearer good-token");

        filter.doFilter(request, response, chain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getPrincipal()).isEqualTo(jwtUser);
        assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
        assertThat(chain.getRequest()).isNotNull();
        assertThat(request.getAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE)).isNull();
    }

    @Test
    void theBearerSchemeIsCaseInsensitive() throws Exception {
        when(jwtService.getUserFromToken("good-token")).thenReturn(new JwtUser(UUID.randomUUID(), List.of()));
        request.addHeader("Authorization", "bearer good-token");

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void withoutAHeaderTheRequestContinuesUnauthenticated() throws Exception {
        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE)).isNull();
        assertThat(chain.getRequest()).isNotNull();
        verifyNoInteractions(jwtService);
    }

    @Test
    void anotherAuthenticationSchemeIsIgnored() throws Exception {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE)).isNull();
        assertThat(chain.getRequest()).isNotNull();
        verifyNoInteractions(jwtService);
    }

    @Test
    void invalidTokenIsRememberedForTheEntryPointAndTheRequestContinues() throws Exception {
        when(jwtService.getUserFromToken("bad-token")).thenThrow(new GeneralException(ErrorCode.INVALID_TOKEN));
        request.addHeader("Authorization", "Bearer bad-token");

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE)).isEqualTo(ErrorCode.INVALID_TOKEN);
        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void expiredTokenIsRememberedAsExpired() throws Exception {
        when(jwtService.getUserFromToken("old-token")).thenThrow(new GeneralException(ErrorCode.TOKEN_EXPIRED));
        request.addHeader("Authorization", "Bearer old-token");

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE)).isEqualTo(ErrorCode.TOKEN_EXPIRED);
    }

    @Test
    void anEmptyBearerValueCountsAsAnInvalidToken() throws Exception {
        when(jwtService.getUserFromToken("")).thenThrow(new GeneralException(ErrorCode.INVALID_TOKEN));
        request.addHeader("Authorization", "Bearer ");

        filter.doFilter(request, response, chain);

        assertThat(request.getAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE)).isEqualTo(ErrorCode.INVALID_TOKEN);
    }

    @Test
    void aServerSideFailureIsNotHiddenAsAnAuthenticationProblem() {
        when(jwtService.getUserFromToken("any-token")).thenThrow(new GeneralException(ErrorCode.INTERNAL_ERROR));
        request.addHeader("Authorization", "Bearer any-token");

        assertThatThrownBy(() -> filter.doFilter(request, response, chain))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR));
    }
}
