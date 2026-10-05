package com.example.identity_service.controller;

import com.example.identity_service.config.OAuthStateCookieFactory;
import com.example.identity_service.config.PendingLinkCookieFactory;
import com.example.identity_service.config.RefreshTokenCookieFactory;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.OAuth2LoginProperties;
import com.example.identity_service.service.oauth2.ExternalLoginResult;
import com.example.identity_service.service.oauth2.GoogleLoginFlow;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Login with Google. Both endpoints are navigations of the browser, not calls of the SPA's JavaScript, so
 * they answer with redirects, never with JSON: whatever happens, the user ends up back on the SPA.
 *
 * The SPA starts the login by sending the browser to {@code /authorize}, and Google sends it back to
 * {@code /callback}. The tokens do not travel in the address: the refresh token is put in its cookie and
 * the SPA, as it does whenever it opens, calls /refresh to get the access token.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth/oauth2/google")
public class GoogleAuthController {

    // The values of ?error= on the SPA's login page. The reason is never put in the address.
    static final String ERROR_ACCESS_DENIED = "access_denied";
    static final String ERROR_LOGIN_FAILED = "login_failed";
    static final String ERROR_SERVER = "server_error";

    private final GoogleLoginFlow googleLoginFlow;
    private final OAuthStateCookieFactory stateCookies;
    private final PendingLinkCookieFactory linkCookies;
    private final RefreshTokenCookieFactory refreshCookies;
    private final OAuth2LoginProperties loginProperties;

    public GoogleAuthController(GoogleLoginFlow googleLoginFlow, OAuthStateCookieFactory stateCookies,
            PendingLinkCookieFactory linkCookies, RefreshTokenCookieFactory refreshCookies,
            OAuth2LoginProperties loginProperties) {
        this.googleLoginFlow = googleLoginFlow;
        this.stateCookies = stateCookies;
        this.linkCookies = linkCookies;
        this.refreshCookies = refreshCookies;
        this.loginProperties = loginProperties;
    }

    @GetMapping("/authorize")
    public ResponseEntity<Void> authorize() {
        GoogleLoginFlow.Start start = googleLoginFlow.start();

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(start.authorizationUrl()))
                .header(HttpHeaders.SET_COOKIE, stateCookies.create(start.stateCookieValue()).toString())
                .build();
    }

    @GetMapping("/callback")
    public ResponseEntity<Void> callback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            // Google sends this instead of a code when the user said no, or something went wrong there
            @RequestParam(required = false) String error,
            @CookieValue(name = OAuthStateCookieFactory.COOKIE_NAME, required = false) String stateCookie) {
        if (error != null) {
            log.info("Google returned an error instead of a code: {}", error);
            return redirectToLogin("access_denied".equals(error) ? ERROR_ACCESS_DENIED : ERROR_LOGIN_FAILED);
        }

        try {
            GoogleLoginFlow.Completed completed = googleLoginFlow.complete(code, state, stateCookie);

            if (completed.status() == ExternalLoginResult.Status.LINK_REQUIRED) {
                // No session. The SPA asks the user whether to link the accounts and for the password of
                // the existing one; what Google proved waits in the cookie meanwhile.
                return redirect("/link-account", linkCookies.create(completed.pendingLinkCookieValue()));
            }

            // A confirmation left over from an earlier attempt is of no use any more.
            return redirect("/", linkCookies.clear(), refreshCookies.create(completed.tokens().refreshToken()));
        } catch (GeneralException e) {
            // Details are in the logs of the step that failed. The user only learns that it did not work.
            return redirectToLogin(e.getErrorCode() == ErrorCode.INTERNAL_ERROR ? ERROR_SERVER : ERROR_LOGIN_FAILED);
        } catch (RuntimeException e) {
            log.error("Unexpected failure while finishing the login with Google", e);
            return redirectToLogin(ERROR_SERVER);
        }
    }

    private ResponseEntity<Void> redirectToLogin(String error) {
        return redirect("/login?error=" + URLEncoder.encode(error, StandardCharsets.UTF_8), linkCookies.clear());
    }

    // Always deletes the state cookie: the login attempt is over, however it ended.
    private ResponseEntity<Void> redirect(String path, ResponseCookie... cookies) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(loginProperties.frontendLocation(path)))
                .header(HttpHeaders.SET_COOKIE, stateCookies.clear().toString());
        for (ResponseCookie cookie : cookies) {
            response.header(HttpHeaders.SET_COOKIE, cookie.toString());
        }
        return response.build();
    }
}
