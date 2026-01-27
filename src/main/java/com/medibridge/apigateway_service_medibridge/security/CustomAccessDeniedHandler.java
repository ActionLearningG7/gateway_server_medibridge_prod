package com.medibridge.apigateway_service_medibridge.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom Access Denied Handler for API Gateway
 *
 * Returns JSON 403 response without triggering browser auth dialogs
 */
@Component
@Slf4j
public class CustomAccessDeniedHandler implements ServerAccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        log.warn("Access denied: {} for path: {}",
            denied.getMessage(),
            exchange.getRequest().getPath());

        // Set response status to 403
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);

        // Set Content-Type to application/json
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // Create JSON error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", Instant.now().toString());
        errorResponse.put("status", 403);
        errorResponse.put("error", "Forbidden");
        errorResponse.put("message", "Access denied. You do not have permission to access this resource.");
        errorResponse.put("path", exchange.getRequest().getPath().value());

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (Exception e) {
            log.error("Error writing access denied response", e);
            byte[] fallbackBytes = "{\"error\":\"Forbidden\"}".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(fallbackBytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        }
    }
}
