package com.example.identity_service.service.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.User;
import com.example.identity_service.model.UserIdentity;
import com.example.identity_service.repository.UserIdentityRepository;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.AuthenticationService;
import com.example.identity_service.service.authentication.PasswordChecker;

// Against the real Postgres, every call really committed, as for the sign-in service. Random data, deleted
// afterwards (deleting a user deletes its identities too).
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import({ AccountLinkService.class, PendingLinkService.class, PasswordChecker.class,
        AccountLinkServiceIntegrationTest.Settings.class })
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AccountLinkServiceIntegrationTest {

    @TestConfiguration
    static class Settings {
        @Bean
        PasswordEncoder passwordEncoder() {
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }

        @Bean
        JwtProperties jwtProperties() {
            return new JwtProperties("link-test-secret-".repeat(4), Duration.ofMinutes(15));
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }

    private static final String PASSWORD = "S3cure-pass!";

    @Autowired
    private AccountLinkService service;

    @Autowired
    private PendingLinkService pendingLinkService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private PasswordEncoder encoder;

    @MockitoBean
    private AuthenticationService authenticationService;

    private final String suffix = UUID.randomUUID().toString().substring(0, 8);
    private final String email = "link_" + suffix + "@example.com";
    private final String otherEmail = "other_" + suffix + "@example.com";
    private final String subject = "sub-" + suffix;
    private final AuthTokens tokens = new AuthTokens("access", "refresh", "Bearer", 900);

    @BeforeEach
    void stubTokens() {
        when(authenticationService.loginAs(any())).thenReturn(tokens);
    }

    @AfterEach
    void cleanUp() {
        userRepository.findByEmail(email).ifPresent(userRepository::delete);
        userRepository.findByEmail(otherEmail).ifPresent(userRepository::delete);
    }

    // ---- the owner confirms ----------------------------------------------------------------------

    @Test
    void theRightPasswordLinksTheAccountAndSignsTheUserIn() {
        User existing = userWithPassword(email, true);

        AuthTokens result = service.link(cookie(), PASSWORD);

        assertThat(result).isEqualTo(tokens);
        UserIdentity link = userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject).orElseThrow();
        assertThat(link.getUser().getId()).isEqualTo(existing.getId());
        assertThat(link.getEmail()).isEqualTo(email);
        verify(authenticationService).loginAs(any(User.class));
    }

    // Once linked, the next sign-in with Google finds the user directly, no confirmation any more.
    @Test
    void confirmingTwiceIsHarmless() {
        User existing = userWithPassword(email, true);

        service.link(cookie(), PASSWORD);
        service.link(cookie(), PASSWORD);

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject).orElseThrow()
                .getUser().getId()).isEqualTo(existing.getId());
    }

    // ---- the password is not the owner's ---------------------------------------------------------

    @Test
    void aWrongPasswordLinksNothingAndSignsNobodyIn() {
        userWithPassword(email, true);

        assertInvalidCredentials("not-the-password");

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject)).isEmpty();
        verify(authenticationService, never()).loginAs(any());
    }

    // A user who has no password (created by a sign-in with Google) cannot confirm anything with one.
    @Test
    void aUserWithoutAPasswordCannotBeLinkedThisWay() {
        userRepository.save(User.builder().email(email).passwordHash(null).build());

        assertInvalidCredentials(PASSWORD);

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject)).isEmpty();
        verify(authenticationService, never()).loginAs(any());
    }

    @Test
    void aDisabledUserCannotBeLinkedEvenWithTheRightPassword() {
        userWithPassword(email, false);

        assertInvalidCredentials(PASSWORD);

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject)).isEmpty();
    }

    @Test
    void anAccountThatNoLongerExistsIsRefusedLikeAWrongPassword() {
        assertInvalidCredentials(PASSWORD);

        verify(authenticationService, never()).loginAs(any());
    }

    // ---- the link would clash with another -------------------------------------------------------

    @Test
    void anExternalAccountAlreadyLinkedToAnotherUserIsNotMoved() {
        User existing = userWithPassword(email, true);
        User owner = userRepository.save(User.builder().email(otherEmail).build());
        userIdentityRepository.save(UserIdentity.builder().user(owner).provider(AuthProvider.GOOGLE)
                .providerUserId(subject).email(otherEmail).build());

        assertThatThrownBy(() -> service.link(cookie(), PASSWORD))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.IDENTITY_ALREADY_LINKED));

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject).orElseThrow()
                .getUser().getId()).isEqualTo(owner.getId()).isNotEqualTo(existing.getId());
        verify(authenticationService, never()).loginAs(any());
    }

    // One Google account per user: a second one would be refused by the database, and so by the service.
    @Test
    void aUserWhoAlreadyHasAnotherGoogleAccountCannotLinkASecondOne() {
        User existing = userWithPassword(email, true);
        userIdentityRepository.save(UserIdentity.builder().user(existing).provider(AuthProvider.GOOGLE)
                .providerUserId("another-" + subject).email(email).build());

        assertThatThrownBy(() -> service.link(cookie(), PASSWORD))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.IDENTITY_ALREADY_LINKED));

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject)).isEmpty();
        verify(authenticationService, never()).loginAs(any());
    }

    // ---- the confirmation itself -----------------------------------------------------------------

    @Test
    void withoutAValidConfirmationNothingIsCheckedOrLinked() {
        userWithPassword(email, true);

        for (String bad : new String[] { null, "", "garbage", cookieOf(new ExternalIdentity(AuthProvider.GITHUB, subject, email)) + "x" }) {
            assertThatThrownBy(() -> service.link(bad, PASSWORD))
                    .isInstanceOfSatisfying(GeneralException.class,
                            ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_LINK_REQUEST));
        }

        verify(authenticationService, never()).loginAs(any());
    }

    // The account to link is the one with the email in the confirmation, never one the browser names.
    @Test
    void theAccountIsFoundByTheEmailInTheConfirmation() {
        userWithPassword(otherEmail, true);
        userWithPassword(email, true);

        service.link(cookie(), PASSWORD);

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject).orElseThrow()
                .getUser().getEmail()).isEqualTo(email);
    }

    // ---- two requests at once --------------------------------------------------------------------

    @Test
    void twoConfirmationsAtTheSameMomentLinkOnceAndBothSucceed() throws Exception {
        User existing = userWithPassword(email, true);
        String cookie = cookie();
        int threads = 2;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch go = new CountDownLatch(1);
        try {
            List<Future<AuthTokens>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    go.await();
                    return service.link(cookie, PASSWORD);
                }));
            }
            go.countDown();

            for (Future<AuthTokens> result : results) {
                assertThat(result.get()).isEqualTo(tokens);
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, subject).orElseThrow()
                .getUser().getId()).isEqualTo(existing.getId());
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private User userWithPassword(String userEmail, boolean enabled) {
        return userRepository.save(User.builder().email(userEmail).passwordHash(encoder.encode(PASSWORD)).enabled(enabled).build());
    }

    private String cookie() {
        return cookieOf(new ExternalIdentity(AuthProvider.GOOGLE, subject, email));
    }

    private String cookieOf(ExternalIdentity identity) {
        return pendingLinkService.start(identity);
    }

    private void assertInvalidCredentials(String password) {
        assertThatThrownBy(() -> service.link(cookie(), password))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }
}
