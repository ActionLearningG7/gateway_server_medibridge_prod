package com.medibridge.apigateway_service_medibridge.config;

import com.medibridge.apigateway_service_medibridge.security.CustomAccessDeniedHandler;
import com.medibridge.apigateway_service_medibridge.security.CustomAuthenticationEntryPoint;
import com.medibridge.apigateway_service_medibridge.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Centralized Security Configuration for API Gateway
 * 
 * Manages:
 * - JWT Authentication for all microservices
 * - CORS Configuration
 * - Role-based Authorization
 * - Public vs Protected Endpoints
 */
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        private final JwtAuthenticationFilter jwtAuthenticationFilter;
        private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
        private final CustomAccessDeniedHandler customAccessDeniedHandler;

        @Bean
        public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
                http
                                // CORS is handled by Spring Cloud Gateway globalcors configuration
                                // Do NOT set CORS configuration here to avoid duplicate headers
                                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                // Disabled - using JWT authentication
                                // Stateless session - no session creation
                                .securityContextRepository(
                                                org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
                                                                .getInstance())
                                .authorizeExchange(exchange -> exchange
                                                // ============================================
                                                // PUBLIC ENDPOINTS (No Authentication Required)
                                                // ============================================

                                                // User Service - Authentication endpoints (both with and without /users
                                                // prefix)
                                                .pathMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/auth/refresh").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/auth/forgot-password")
                                                .permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/auth/reset-password")
                                                .permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/auth/verify-email").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/users/auth/login").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/users/auth/register")
                                                .permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/users/auth/refresh").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/users/auth/forgot-password")
                                                .permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/v1/users/auth/reset-password")
                                                .permitAll()

                                                // ============================================
                                                // CORS PREFLIGHT REQUESTS
                                                // ============================================
                                                // Allow OPTIONS for all paths (CORS preflight handshake)
                                                // The gateway will return proper CORS headers
                                                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                                                // Actuator endpoints
                                                .pathMatchers("/actuator/**").permitAll()

                                                // Doctor Service - Public Access
                                                .pathMatchers(HttpMethod.GET, "/api/v1/doctors").permitAll()
                                                .pathMatchers(HttpMethod.GET, "/api/v1/doctors/available").permitAll()
                                                .pathMatchers(HttpMethod.GET, "/api/v1/doctors/emergency").permitAll()
                                                .pathMatchers(HttpMethod.GET, "/api/v1/doctors/specialization/**")
                                                .permitAll()
                                                .pathMatchers(HttpMethod.GET, "/api/v1/doctors/{id:[a-f0-9-]{36}}")
                                                .permitAll() // Secure UUID pattern

                                                // Eureka endpoints
                                                .pathMatchers("/eureka/**").permitAll()

                                                // ============================================
                                                // WEBSOCKET ENDPOINTS (SockJS Handshake)
                                                // ============================================
                                                // Allow SockJS handshake at HTTP level (no JWT required for /ws/**)
                                                // STOMP CONNECT authentication is handled by WebSocketAuthInterceptor
                                                // Includes:
                                                // - GET /ws/info (SockJS handshake)
                                                // - /ws/{server-id}/{session-id}/xhr (XHR transport)
                                                // - All OPTIONS for CORS preflight
                                                // - All POST for SockJS transports
                                                .pathMatchers("/ws/**").permitAll()
                                                .pathMatchers("/ws-lab/**").permitAll()
                                                .pathMatchers("/api/ws/**").permitAll()
                                                .pathMatchers("/api/ws/info/**").permitAll()
                                                .pathMatchers(HttpMethod.OPTIONS, "/ws/**").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/ws/**").permitAll()
                                                .pathMatchers(HttpMethod.OPTIONS, "/api/ws/**").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/ws/**").permitAll()
                                                .pathMatchers(HttpMethod.OPTIONS, "/ws-lab/**").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/ws-lab/**").permitAll()
                                                .pathMatchers("/api/ws-lab/**").permitAll()
                                                .pathMatchers(HttpMethod.OPTIONS, "/api/ws-lab/**").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/api/ws-lab/**").permitAll()
                                                .pathMatchers("/ws-sos/**").permitAll()
                                                .pathMatchers(HttpMethod.OPTIONS, "/ws-sos/**").permitAll()
                                                .pathMatchers(HttpMethod.POST, "/ws-sos/**").permitAll()

                                                // Organization Address (Public)
                                                .pathMatchers(HttpMethod.GET, "/api/v1/organization/**")
                                                .permitAll()

                                                // ============================================
                                                // ADMIN ONLY ENDPOINTS
                                                // ============================================

                                                // User Service - Admin operations
                                                .pathMatchers("/api/v1/users/admin/**").hasRole("ADMIN")

                                                // All services - Admin endpoints
                                                .pathMatchers("/api/v1/*/admin/**").hasRole("ADMIN")

                                                // ============================================
                                                // DOCTOR ONLY ENDPOINTS
                                                // ============================================

                                                // Appointment Service - Doctor operations
                                                .pathMatchers(HttpMethod.GET, "/api/v1/appointments/doctor/**")
                                                .hasRole("DOCTOR")
                                                .pathMatchers(HttpMethod.PUT, "/api/v1/appointments/doctor/**")
                                                .hasRole("DOCTOR")

                                                // Prescription Service - Doctor operations
                                                .pathMatchers(HttpMethod.POST, "/api/v1/prescriptions/**")
                                                .hasRole("DOCTOR")
                                                .pathMatchers(HttpMethod.PUT, "/api/v1/prescriptions/**")
                                                .hasRole("DOCTOR")

                                                // Lab Service - Doctor operations
                                                .pathMatchers(HttpMethod.POST, "/api/v1/lab/orders/**")
                                                .hasRole("DOCTOR")
                                                .pathMatchers(HttpMethod.GET, "/api/v1/lab/orders/doctor/**")
                                                .hasRole("DOCTOR")

                                                // Reports Service - Doctor operations
                                                .pathMatchers(HttpMethod.POST, "/api/v1/reports/**").hasRole("DOCTOR")
                                                .pathMatchers(HttpMethod.GET, "/api/v1/reports/doctor/**")
                                                .hasRole("DOCTOR")

                                                // ============================================
                                                // PATIENT ONLY ENDPOINTS
                                                // ============================================

                                                // Appointment Service - Patient operations
                                                .pathMatchers(HttpMethod.POST, "/api/v1/appointments/patient/**")
                                                .hasRole("PATIENT")
                                                .pathMatchers(HttpMethod.GET, "/api/v1/appointments/patient/**")
                                                .hasRole("PATIENT")
                                                .pathMatchers(HttpMethod.DELETE, "/api/v1/appointments/patient/**")
                                                .hasRole("PATIENT")

                                                // SOS/Ambulance Service - Patient operations
                                                .pathMatchers(HttpMethod.POST, "/api/v1/sos/**").hasRole("PATIENT")

                                                // ============================================
                                                // AUTHENTICATED ENDPOINTS (Any logged-in user)
                                                // ============================================

                                                // User Service - Profile operations
                                                .pathMatchers("/api/v1/users/profile/**").authenticated()
                                                .pathMatchers("/api/v1/users/auth/change-password").authenticated()
                                                .pathMatchers("/api/v1/users/auth/logout").authenticated()

                                                // Appointment Service - General operations
                                                .pathMatchers(HttpMethod.GET, "/api/v1/appointments/**").authenticated()

                                                // Lab Service - View results
                                                .pathMatchers(HttpMethod.GET, "/api/v1/lab/results/**").authenticated()

                                                // Reports Service - View reports
                                                .pathMatchers(HttpMethod.GET, "/api/v1/reports/**").authenticated()

                                                // Prescription Service - View prescriptions
                                                .pathMatchers(HttpMethod.GET, "/api/v1/prescriptions/**")
                                                .authenticated()

                                                // ============================================
                                                // DEFAULT: Require authentication for all other endpoints
                                                // ============================================
                                                .anyExchange().authenticated())
                                // Configure exception handling to prevent browser auth popup
                                .exceptionHandling(exceptions -> exceptions
                                                .authenticationEntryPoint(customAuthenticationEntryPoint)
                                                .accessDeniedHandler(customAccessDeniedHandler))
                                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                                // Add JWT filter
                                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);

                return http.build();
        }

        /**
         * CORS Configuration is now handled centrally by Spring Cloud Gateway
         * See: application-dev.yml, application-prod.yml, application-test.yml
         */

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("http://localhost:3000","https://medibridge-prod.vercel.app/"));
                config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
                config.setExposedHeaders(List.of("Authorization", "Content-Disposition", "Content-Type"));
                config.setAllowCredentials(true);
                config.addAllowedHeader("*");
                config.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", config);
                return source;
        }

}
