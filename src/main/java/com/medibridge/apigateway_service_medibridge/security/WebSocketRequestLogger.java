package com.medibridge.apigateway_service_medibridge.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * WebSocket Request Logger
 * Logs all /ws/** requests for debugging SockJS handshake issues
 */
@Component
@Slf4j
public class WebSocketRequestLogger implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        String method = String.valueOf(exchange.getRequest().getMethod());

        // Log WebSocket handshake requests
        if (path.contains("/ws/")) {
            log.info("=== WebSocket Request ===");
            log.info("  Method: {}", method);
            log.info("  Path: {}", path);
            log.info("  Query: {}", exchange.getRequest().getQueryParams());
            log.info("  Host: {}", exchange.getRequest().getHeaders().getHost());
            log.info("  Authorization: {}", 
                exchange.getRequest().getHeaders().getFirst("Authorization") != null ? "Present" : "Missing");
            log.info("  Connection: {}", exchange.getRequest().getHeaders().getFirst("Connection"));
            log.info("  Upgrade: {}", exchange.getRequest().getHeaders().getFirst("Upgrade"));
        }

        // Continue with response and log status
        return chain.filter(exchange).doFinally(signal -> {
            if (path.contains("/ws/")) {
                log.info("  Response Status: {}", exchange.getResponse().getStatusCode());
            }
        });
    }
}
