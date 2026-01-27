package com.medibridge.apigateway_service_medibridge.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom Authentication Entry Point for API Gateway
 *
 * Returns JSON 401 response WITHOUT "WWW-Authenticate: Basic" header
 * This prevents browser from showing the basic auth popup dialog
 */
@Component
@Slf4j
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        log.warn("Authentication failed: {} for path: {}",
            ex.getMessage(),
            exchange.getRequest().getPath());

        // Set response status to 401
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);

        // Set Content-Type to application/json
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // IMPORTANT: Do NOT set WWW-Authenticate header to prevent browser popup
        // exchange.getResponse().getHeaders().set("WWW-Authenticate", "..."); // DON'T DO THIS

        // Create JSON error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", Instant.now().toString());
        errorResponse.put("status", 401);
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", "Authentication required. Please provide valid credentials.");
        errorResponse.put("path", exchange.getRequest().getPath().value());

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (Exception e) {
            log.error("Error writing authentication error response", e);
            byte[] fallbackBytes = "{\"error\":\"Unauthorized\"}".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(fallbackBytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        }
    }
}
