package com.example.identity_service.service.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.example.identity_service.model.UserIdentity;
import com.example.identity_service.repository.UserIdentityRepository;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.impl.RoleServiceImpl;
import com.example.identity_service.service.oauth2.ExternalLoginResult.Status;

// Against the real Postgres, with every call really committed: what is tested is what the database does
// when requests meet. Data uses random values and is deleted afterwards, so the dev database is left as it
// was; deleting a user also deletes its identities (ON DELETE CASCADE).
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import({ ExternalLoginService.class, RoleServiceImpl.class })
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class ExternalLoginServiceIntegrationTest {

    @Autowired
    private ExternalLoginService service;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    private final String suffix = UUID.randomUUID().toString().substring(0, 8);
    private final String email = "google_" + suffix + "@example.com";
    private final String subject = "sub-" + suffix;

    @AfterEach
    void cleanUp() {
        userRepository.findByEmail(email).ifPresent(userRepository::delete);
    }

    // ---- the email is not known ------------------------------------------------------------------

    @Test
    void anUnknownEmailCreatesAUserWithoutAPasswordAndLinksTheAccount() {
        ExternalLoginResult result = service.signIn(identity());

        assertThat(result.status()).isEqualTo(Status.ACCOUNT_CREATED);
        User stored = userRepository.findByEmail(email).orElseThrow();
        assertThat(stored.getId()).isEqualTo(result.user().getId());
        assertThat(stored.getPasswordHash()).isNull();
        assertThat(stored.isEnabled()).isTrue();
        assertThat(stored.getRoles()).extracting(Role::getName).containsExactly(RoleEnum.USER);
        UserIdentity link = userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject).orElseThrow();
        assertThat(link.getUser().getId()).isEqualTo(stored.getId());
        assertThat(link.getEmail()).isEqualTo(email);
    }

    // ---- the account is already linked -----------------------------------------------------------

    @Test
    void aLinkedAccountSignsTheSameUserInAgain() {
        ExternalLoginResult first = service.signIn(identity());

        ExternalLoginResult second = service.signIn(identity());

        assertThat(second.status()).isEqualTo(Status.SIGNED_IN);
        assertThat(second.user().getId()).isEqualTo(first.user().getId());
    }

    // The link is matched on the provider's stable id, not on the email: the email can change at Google.
    @Test
    void aLinkedAccountIsFoundByItsIdEvenIfItsEmailChanged() {
        ExternalLoginResult first = service.signIn(identity());

        ExternalLoginResult later = service.signIn(new ExternalIdentity(AuthProvider.GOOGLE, subject, "new_" + email));

        assertThat(later.status()).isEqualTo(Status.SIGNED_IN);
        assertThat(later.user().getId()).isEqualTo(first.user().getId());
        assertThat(userRepository.findByEmail("new_" + email)).isEmpty(); // no second user was made
    }

    @Test
    void aDisabledUserCannotSignIn() {
        User user = service.signIn(identity()).user();
        user.setEnabled(false);
        userRepository.save(user);

        assertThatThrownBy(() -> service.signIn(identity()))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }

    // ---- the email belongs to an existing user ---------------------------------------------------

    @Test
    void anEmailOfAUserWithAPasswordMustBeLinkedByItsOwnerAndNothingChanges() {
        User existing = userRepository.save(User.builder().email(email).passwordHash("{x}original-hash").build());

        ExternalLoginResult result = service.signIn(identity());

        assertThat(result.status()).isEqualTo(Status.LINK_REQUIRED);
        assertThat(result.user()).isNull();
        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject)).isEmpty();
        assertThat(userRepository.findByEmail(email).orElseThrow().getPasswordHash()).isEqualTo("{x}original-hash");
        assertThat(userRepository.findByEmail(email).orElseThrow().getId()).isEqualTo(existing.getId());
    }

    @Test
    void theEmailIsComparedIgnoringCase() {
        userRepository.save(User.builder().email(email.toUpperCase()).passwordHash("{x}hash").build());

        assertThat(service.signIn(identity()).status()).isEqualTo(Status.LINK_REQUIRED);
    }

    // ---- requests that meet ----------------------------------------------------------------------

    // The first login of a new user, sent several times at the same moment (several tabs, a double click).
    // Exactly one creates the user; the others must end up signed in as that user, never in an error and
    // never in "link required" for an email that was just created for this very account.
    @Test
    void whenTheSameNewUserLogsInSeveralTimesAtOnceOnlyOneUserIsCreated() throws Exception {
        int threads = 8;
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<ExternalLoginResult>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Callable<ExternalLoginResult> login = () -> {
                    go.await();
                    return service.signIn(identity());
                };
                futures.add(pool.submit(login));
            }
            go.countDown();

            List<ExternalLoginResult> results = new ArrayList<>();
            for (Future<ExternalLoginResult> future : futures) {
                results.add(future.get());
            }

            assertThat(results).filteredOn(r -> r.status() == Status.ACCOUNT_CREATED).hasSize(1);
            assertThat(results).filteredOn(r -> r.status() == Status.SIGNED_IN).hasSize(threads - 1);
            assertThat(results).extracting(r -> r.user().getId()).containsOnly(results.get(0).user().getId());
        } finally {
            pool.shutdownNow();
        }
    }

    private ExternalIdentity identity() {
        return new ExternalIdentity(AuthProvider.GOOGLE, subject, email);
    }
}
