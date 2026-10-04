package com.example.identity_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.example.identity_service.model.CorsProperties;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.example.identity_service.service.authentication.JwtService;
import com.example.identity_service.controller.AuthController;

import java.time.Duration;
import java.util.List;

@EnableWebSecurity
@EnableMethodSecurity // turns on @PreAuthorize on controller and service methods
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            JwtService jwtService,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler,
            CorsConfigurationSource corsConfigurationSource
    ) throws Exception {
        httpSecurity
                // lets the SPA, served from another origin, call this API: answers the browser's preflight requests
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
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

    // Only the origins listed in app.security.cors.allowed-origins may call this API from a browser.
    // Credentials must be allowed or the browser will neither send nor accept the refresh cookie, and for
    // that reason the origins are exact: a wildcard together with credentials is refused by browsers.
    @Bean
    public CorsConfigurationSource corsConfigurationSource(CorsProperties corsProperties) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        if (corsProperties.allowedOrigins().isEmpty()) {
            return source; // no CORS rules: only same-origin browser calls work
        }

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(corsProperties.allowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", AuthController.CSRF_HEADER));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(Duration.ofHours(1));
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}
