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
import org.springframework.util.StringUtils;

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

    @Value("${jwt.secret:changemechangemechangemechangeme}")
    private String jwtSecret;
    @Value("${jwt.ttl:3600000}")
    private Long jwtTimeToLive;

    private final UserDetailsService userDetailsService;

    @PostConstruct
    public void init() {
        byte[] bytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        jwtSecret = Base64.getEncoder().encodeToString(bytes);
    }

    public String generateToken(String username, Collection<? extends Role> roles) {
        Instant issuedAt = Instant.now();
        Instant expiration = issuedAt.plusMillis(jwtTimeToLive);
        Set<String> roleNames = roles.stream()
                .map(Role::getName)
                .map(Enum::name)
                .collect(Collectors.toSet());
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .claim(ROLES_CLAIM, roleNames)
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(expiration))
                .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public boolean isValid(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
        return true;
    }

    public Authentication getAuthentication(String token) {
        var claims = retrieveBody(token);
        if (claims.getExpiration().toInstant().isBefore(Instant.now())) {
            throw new JwtValidationException("The token has expired");
        }
        var username = claims.getSubject();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    private Claims retrieveBody(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtValidationException("Invalid token");
        }
    }

}
