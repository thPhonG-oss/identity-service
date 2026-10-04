package com.example.identity_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.example.identity_service.service.authentication.JwtService;

@EnableWebSecurity
@EnableMethodSecurity // turns on @PreAuthorize on controller and service methods
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            JwtService jwtService,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable) // method reference <=> crst -> csrf.disable() -> remove CsrtFilter out of SecurityFilterChain
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/api/v1/auth/**").permitAll()
                            // roles are a management concern: only admins list them
                            .requestMatchers("/api/v1/roles/**").hasRole("ADMIN")
                            .anyRequest().authenticated();
                })
                .sessionManagement((sessionManagement) -> {
                    sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS); //Spring Security will never create an HttpSession and it will never use it to obtain the SecurityContext
                })
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        // 401 for a request that needs authentication and has none (or a rejected token)
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                        // 403 for an authenticated user who lacks the required authority
                        .accessDeniedHandler(jwtAccessDeniedHandler))
                // reads the bearer token before Spring's own login filter would run
                .addFilterBefore(new JwtAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class)
        ;

        return httpSecurity.build();
    }
}
