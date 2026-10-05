package com.example.identity_service.service.oauth2;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.User;
import com.example.identity_service.model.UserIdentity;
import com.example.identity_service.repository.UserIdentityRepository;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.AuthenticationService;
import com.example.identity_service.service.authentication.PasswordChecker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;

/**
 * The last step of a sign-in with an external provider whose email belongs to an existing user: the user
 * confirms with the password of that account, and the external account is linked to it.
 *
 * Without the password, anyone able to get a provider account with that email could take the account over:
 * nothing proves the email was verified when the account was registered here.
 */
@Slf4j
@Service
public class AccountLinkService {

    private final PendingLinkService pendingLinkService;
    private final UserRepository userRepository;
    private final UserIdentityRepository userIdentityRepository;
    private final PasswordChecker passwordChecker;
    private final AuthenticationService authenticationService;
    private final TransactionTemplate transactionTemplate;

    public AccountLinkService(PendingLinkService pendingLinkService, UserRepository userRepository,
            UserIdentityRepository userIdentityRepository, PasswordChecker passwordChecker,
            AuthenticationService authenticationService, TransactionTemplate transactionTemplate) {
        this.pendingLinkService = pendingLinkService;
        this.userRepository = userRepository;
        this.userIdentityRepository = userIdentityRepository;
        this.passwordChecker = passwordChecker;
        this.authenticationService = authenticationService;
        this.transactionTemplate = transactionTemplate;
    }

    /** What the SPA may show on the confirmation page. */
    public ExternalIdentity pending(String pendingLinkCookie) {
        return pendingLinkService.resume(pendingLinkCookie);
    }

    /**
     * Links the external account kept in the cookie to the user with the same email, if the password is that
     * user's, and signs them in.
     *
     * @throws GeneralException INVALID_LINK_REQUEST when the cookie is not valid; INVALID_CREDENTIALS when the
     *                          password is wrong or the account cannot be used (one answer for all of them);
     *                          IDENTITY_ALREADY_LINKED when the link would clash with another one
     */
    public AuthTokens link(String pendingLinkCookie, String password) {
        ExternalIdentity identity = pendingLinkService.resume(pendingLinkCookie);

        // The account is looked for by the email Google vouched for, never by anything the browser sends.
        User user = userRepository.findByEmail(identity.email()).orElse(null);

        // The password is checked with the same rules as a login: the same work whatever the account is, one
        // answer for every failure, the account state only after the password.
        PasswordChecker.Result result = passwordChecker.check(user, password);
        if (result != PasswordChecker.Result.MATCH) {
            throw rejected("password check failed: " + result);
        }
        if (!user.isEnabled()) {
            throw rejected("account disabled");
        }

        addLink(user, identity);
        log.info("Linked a {} account to user {}", identity.provider(), user.getId());

        return authenticationService.loginAs(user);
    }

    // Two requests can confirm the same link at the same time (a double click); the database refuses the
    // second insert, at commit. It is caught outside the transaction and the second attempt simply finds the
    // link the first one made. A second refusal is a real clash.
    private void addLink(User user, ExternalIdentity identity) {
        try {
            transactionTemplate.executeWithoutResult(status -> insertLink(user, identity));
        } catch (DataIntegrityViolationException e) {
            log.info("Another request linked the same account at the same moment, looking again");
            try {
                transactionTemplate.executeWithoutResult(status -> insertLink(user, identity));
            } catch (DataIntegrityViolationException second) {
                log.warn("Link refused: the {} account or the user is already linked to another", identity.provider());
                throw new GeneralException(ErrorCode.IDENTITY_ALREADY_LINKED);
            }
        }
    }

    private void insertLink(User user, ExternalIdentity identity) {
        Optional<UserIdentity> existing =
                userIdentityRepository.findByProviderAndProviderUserId(identity.provider(), identity.subject());
        if (existing.isPresent()) {
            if (existing.get().getUser().getId().equals(user.getId())) {
                return; // already linked to this very user: nothing to do
            }
            throw new GeneralException(ErrorCode.IDENTITY_ALREADY_LINKED);
        }

        userIdentityRepository.save(UserIdentity.builder()
                .user(user)
                .provider(identity.provider())
                .providerUserId(identity.subject())
                .email(identity.email())
                .build());
    }

    // The reason is for the operators' log only.
    private GeneralException rejected(String reason) {
        log.warn("Link rejected: {}", reason);
        return new GeneralException(ErrorCode.INVALID_CREDENTIALS);
    }
}
