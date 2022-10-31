package com.example.jwtauth.security.jwt;

import com.example.jwtauth.exception.JwtValidationException;
import com.example.jwtauth.model.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Setter
@Getter
@RequiredArgsConstructor
public class JwtProvider {
    public static final String TOKEN_PREAMBLE = "Bearer ";
    public static final String AUTH_HEADER = HttpHeaders.AUTHORIZATION;
    public static final String ROLES_CLAIM = "Roles";

    @Value("${jwt.access.secret:changemechangemechangemechangeme}")
    private String accessTokenSecret;
    @Value("${jwt.refresh.secret:anothersecretanothersecretanothersecret}")
    private String refreshTokenSecret;
    @Value("${jwt.ttl:600000}") // default 10m
    private Long accessTokenTtl;
    @Value("${jwt.ttl:7200000}") // default 2h
    private Long refreshTokenTtl;

    private final UserDetailsService userDetailsService;

    @PostConstruct
    public void init() {
        accessTokenSecret = Base64.getEncoder()
                .encodeToString(accessTokenSecret.getBytes(StandardCharsets.UTF_8));
        refreshTokenSecret = Base64.getEncoder()
                .encodeToString(refreshTokenSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(String username, Collection<? extends Role> roles) {
        var issuedAt = Instant.now();
        var expiration = issuedAt.plusMillis(accessTokenTtl);
        var roleNames = roles.stream()
                .map(Role::getName)
                .map(Enum::name)
                .collect(Collectors.toSet());
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .claim(ROLES_CLAIM, roleNames)
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(expiration))
                .signWith(Keys.hmacShaKeyFor(accessTokenSecret.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public String generateRefreshToken(String username) {
        var issuedAt = Instant.now();
        var expiration = issuedAt.plusMillis(refreshTokenTtl);
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(expiration))
                .signWith(Keys.hmacShaKeyFor(refreshTokenSecret.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public String extractUsernameFromRefreshToken(String token) {
        return retrieveBody(token, refreshTokenSecret).getSubject();
    }

    public boolean isAccessTokenValid(String token) {
        return isValid(token, accessTokenSecret);
    }

    public boolean isRefreshTokenValid(String token) {
        return isValid(token, refreshTokenSecret);
    }

    private boolean isValid(String token, String secret) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
        return true;
    }

    public Authentication getAuthentication(String token) {
        var claims = retrieveBody(token, accessTokenSecret);
        if (claims.getExpiration().toInstant().isBefore(Instant.now())) {
            throw new JwtValidationException("The token has expired");
        }
        var username = claims.getSubject();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    private Claims retrieveBody(String token, String secret) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtValidationException("Invalid token");
        }
    }

}
