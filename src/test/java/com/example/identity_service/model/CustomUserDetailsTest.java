package com.example.identity_service.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

class CustomUserDetailsTest {

    @Test
    void loginIdentifierIsTheEmail() {
        assertThat(new CustomUserDetails(user(true)).getUsername()).isEqualTo("phong@example.com");
    }

    @Test
    void isEnabledFollowsTheUserFlag() {
        assertThat(new CustomUserDetails(user(true)).isEnabled()).isTrue();
        assertThat(new CustomUserDetails(user(false)).isEnabled()).isFalse();
    }

    @Test
    void authoritiesAreTheRolesWithTheRolePrefix() {
        User user = User.builder()
                .email("phong@example.com")
                .passwordHash("{test}hash")
                .roles(Set.of(new Role((short) 1, RoleEnum.USER), new Role((short) 2, RoleEnum.ADMIN)))
                .build();

        assertThat(new CustomUserDetails(user).getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    private static User user(boolean enabled) {
        return User.builder()
                .email("phong@example.com")
                .passwordHash("{test}hash")
                .enabled(enabled)
                .build();
    }
}
