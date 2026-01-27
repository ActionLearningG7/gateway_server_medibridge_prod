package com.medibridge.apigateway_service_medibridge.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

/**
 * JWT Authentication Filter for API Gateway
 * 
 * Validates JWT tokens and sets authentication context for downstream services
 * Adds user information to request headers for microservices
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // Bypass JWT processing for WebSocket endpoints - they're handled by STOMP
        // SockJS handshake endpoints must not require JWT
        if (isWebSocketPath(path)) {
            log.debug("Bypassing JWT for WebSocket path: {}", path);
            return chain.filter(exchange);
        }

        String token = extractToken(exchange.getRequest());

        if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
            try {
                String email = jwtTokenProvider.getEmailFromToken(token);
                String role = jwtTokenProvider.getRoleFromToken(token);
                String userId = jwtTokenProvider.getUserIdFromToken(token).toString();
                Boolean isAdmin = jwtTokenProvider.getIsAdminFromToken(token);

                // Create authentication object
                List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                        new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email,
                        null, authorities);

                // Add user information to request headers for downstream services
                ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Email", email)
                        .header("X-User-Role", role);

                if (isAdmin != null) {
                    requestBuilder.header("X-Is-Admin", isAdmin.toString());
                }

                ServerHttpRequest mutatedRequest = requestBuilder.build();

                ServerWebExchange mutatedExchange = exchange.mutate()
                        .request(mutatedRequest)
                        .build();

                log.debug("Authenticated user: {} with role: {}", email, role);

                // Set authentication in reactive security context and continue
                return chain.filter(mutatedExchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

            } catch (Exception e) {
                log.error("Error processing JWT token: {}", e.getMessage());
            }
        }

        return chain.filter(exchange);
    }

    /**
     * Check if path is a WebSocket endpoint that should bypass JWT
     */
    private boolean isWebSocketPath(String path) {
        return path.startsWith("/ws") ||
                path.startsWith("/api/ws") ||
                path.startsWith("/api/v1/ws") || path.startsWith("/api/ws/info");
    }

    /**
     * Extract JWT token from Authorization header
     */
    private String extractToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
