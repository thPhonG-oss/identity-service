package com.example.identity_service.service.oauth2;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.JwtProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Remembers, between two requests, an external account that is waiting for its owner to confirm a link.
 *
 * When someone signs in with Google and the email already belongs to a user, nothing may be linked until
 * that user proves they own the account, with its password. Google has already proven who the visitor is, and
 * that must not be asked again, so it is kept here: an encrypted token that goes in a cookie, like the state
 * of the login itself (see {@link OAuthLoginStateService}) but with a key and a purpose of its own, so the
 * two cannot be used in place of each other.
 *
 * The cookie is the only proof that Google vouched for this identity. Because it is encrypted and
 * authenticated, the browser can neither read it nor forge one, and cannot make it name another account.
 */
@Slf4j
@Service
public class PendingLinkService {

    /** The user has this long to enter their password. */
    public static final Duration LINK_TTL = Duration.ofMinutes(10);

    private static final String PURPOSE = "link";

    private final JweSealer sealer;
    private final Clock clock;

    public PendingLinkService(JwtProperties jwtProperties, Clock clock) {
        this.sealer = new JweSealer(jwtProperties.secret(), "identity-service:oauth2-pending-link-cookie");
        this.clock = clock;
    }

    /** @return what to put in the cookie */
    public String start(ExternalIdentity identity) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("purpose", PURPOSE);
        payload.put("provider", identity.provider().name());
        payload.put("sub", identity.subject());
        payload.put("email", identity.email());
        payload.put("exp", Instant.now(clock).plus(LINK_TTL).getEpochSecond());
        return sealer.seal(payload);
    }

    /**
     * @throws GeneralException INVALID_LINK_REQUEST when the cookie is missing, altered, expired or not made
     *                          for this purpose
     */
    public ExternalIdentity resume(String cookieValue) {
        if (cookieValue == null || cookieValue.isBlank()) {
            throw rejected("cookie missing");
        }

        Map<String, Object> payload = sealer.open(cookieValue).orElseThrow(() -> rejected("not valid"));

        if (!PURPOSE.equals(text(payload, "purpose"))) {
            throw rejected("made for another purpose");
        }
        if (!(payload.get("exp") instanceof Number expiresAt)
                || !Instant.now(clock).isBefore(Instant.ofEpochSecond(expiresAt.longValue()))) {
            throw rejected("expired");
        }

        AuthProvider provider;
        try {
            provider = AuthProvider.valueOf(text(payload, "provider"));
        } catch (IllegalArgumentException e) {
            throw rejected("unknown provider");
        }
        return new ExternalIdentity(provider, text(payload, "sub"), text(payload, "email"));
    }

    private String text(Map<String, Object> payload, String name) {
        if (payload.get(name) instanceof String value && !value.isBlank()) {
            return value;
        }
        throw rejected("claim " + name + " missing");
    }

    // The reason is for the operators' log only. The cookie and the identity are never logged.
    private GeneralException rejected(String reason) {
        log.warn("Pending link rejected: {}", reason);
        return new GeneralException(ErrorCode.INVALID_LINK_REQUEST);
    }
}
