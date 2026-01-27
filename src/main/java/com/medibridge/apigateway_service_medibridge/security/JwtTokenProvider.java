package com.medibridge.apigateway_service_medibridge.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * JWT Token Provider for API Gateway
 * 
 * Handles JWT token validation and claims extraction
 * Uses the same secret as the User Service for token validation
 */
@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret:MediBridge2026!Pr0duct1on$ecretK3y#H0sp1talManag3m3ntSyst3m@Secur1ty}")
    private String jwtSecret;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Get user ID from token
     */
    public UUID getUserIdFromToken(String token) {
        Claims claims = getClaims(token);
        return UUID.fromString(claims.getSubject());
    }

    /**
     * Get email from token
     */
    public String getEmailFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("email", String.class);
    }

    /**
     * Get role from token
     */
    public String getRoleFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("role", String.class);
    }

    /**
     * Get isAdmin from token
     */
    public Boolean getIsAdminFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("isAdmin", Boolean.class);
    }

    /**
     * Validate token
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException ex) {
            log.error("JWT token is expired: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("JWT token is unsupported: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
        } catch (SecurityException ex) {
            log.error("Invalid JWT signature: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty: {}", ex.getMessage());
        }
        return false;
    }

    /**
     * Get all claims from token
     */
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Check if token has specific role
     */
    public boolean hasRole(String token, String role) {
        try {
            String tokenRole = getRoleFromToken(token);
            return tokenRole != null && tokenRole.equalsIgnoreCase(role);
        } catch (Exception e) {
            log.error("Error checking role: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if token has any of the specified roles
     */
    public boolean hasAnyRole(String token, String... roles) {
        try {
            String tokenRole = getRoleFromToken(token);
            if (tokenRole == null) {
                return false;
            }
            for (String role : roles) {
                if (tokenRole.equalsIgnoreCase(role)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            log.error("Error checking roles: {}", e.getMessage());
            return false;
        }
    }
}
