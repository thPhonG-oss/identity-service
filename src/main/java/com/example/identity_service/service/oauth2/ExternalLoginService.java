package com.example.identity_service.service.oauth2;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.example.identity_service.model.UserIdentity;
import com.example.identity_service.repository.UserIdentityRepository;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.RoleService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;

/**
 * Decides which user an identity verified by an external provider is, creating the user when needed.
 * Three cases, the same for every provider:
 * <ol>
 *   <li>the provider account is already linked: sign that user in;</li>
 *   <li>the email is not known: create a user without a password, linked to the provider account;</li>
 *   <li>the email belongs to an existing user: change nothing. An email, even one the provider verified,
 *       is not enough to hand over an account that may have been registered with a password, so the owner
 *       must confirm with that password first (LINK_REQUIRED).</li>
 * </ol>
 */
@Slf4j
@Service
public class ExternalLoginService {

    private final UserRepository userRepository;
    private final UserIdentityRepository userIdentityRepository;
    private final RoleService roleService;
    private final TransactionTemplate transactionTemplate;

    public ExternalLoginService(UserRepository userRepository, UserIdentityRepository userIdentityRepository,
            RoleService roleService, TransactionTemplate transactionTemplate) {
        this.userRepository = userRepository;
        this.userIdentityRepository = userIdentityRepository;
        this.roleService = roleService;
        this.transactionTemplate = transactionTemplate;
    }

    // The transaction is opened by hand instead of with @Transactional on purpose. Two requests for the same
    // new user can pass the checks at the same time, and the database then refuses the second insert, at
    // commit. With @Transactional that exception would escape from the method with the transaction already
    // gone; here it is caught outside the transaction, and the second attempt simply finds what the
    // first one created.
    public ExternalLoginResult signIn(ExternalIdentity identity) {
        try {
            return transactionTemplate.execute(status -> resolve(identity));
        } catch (DataIntegrityViolationException e) {
            log.info("Another request created the same user at the same moment, looking again");
            return transactionTemplate.execute(status -> resolve(identity));
        }
    }

    private ExternalLoginResult resolve(ExternalIdentity identity) {
        Optional<UserIdentity> linked = findLinked(identity);
        if (linked.isPresent()) {
            return signedIn(linked.get(), identity);
        }

        if (userRepository.existsByEmail(identity.email())) {
            // Look at the link once more before concluding that the email belongs to someone else. A request
            // for this same new user may have committed it between the two queries above: the user and its
            // link are created in one transaction, so if the email is visible now, the link is too.
            linked = findLinked(identity);
            return linked.isPresent() ? signedIn(linked.get(), identity) : ExternalLoginResult.linkRequired();
        }

        // No password: this user can only sign in through the provider, until a password is set some day.
        User user = User.builder().email(identity.email()).build();
        user.getRoles().add(roleService.getRoleByName(RoleEnum.USER));
        userRepository.save(user);
        userIdentityRepository.save(UserIdentity.builder()
                .user(user)
                .provider(identity.provider())
                .providerUserId(identity.subject())
                .email(identity.email())
                .build());

        return new ExternalLoginResult(ExternalLoginResult.Status.ACCOUNT_CREATED, user);
    }

    private Optional<UserIdentity> findLinked(ExternalIdentity identity) {
        return userIdentityRepository.findByProviderAndProviderUserId(identity.provider(), identity.subject());
    }

    private ExternalLoginResult signedIn(UserIdentity linked, ExternalIdentity identity) {
        User user = linked.getUser();
        if (!user.isEnabled()) {
            log.warn("Login with {} rejected: account disabled", identity.provider());
            throw new GeneralException(ErrorCode.INVALID_CREDENTIALS);
        }
        return new ExternalLoginResult(ExternalLoginResult.Status.SIGNED_IN, user);
    }
}
