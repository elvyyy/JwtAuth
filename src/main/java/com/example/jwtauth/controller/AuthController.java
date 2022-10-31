package com.example.jwtauth.controller;

import com.example.jwtauth.dto.SignInRq;
import com.example.jwtauth.dto.SignUpRq;
import com.example.jwtauth.exception.UsernamePasswordNotExistException;
import com.example.jwtauth.model.Role;
import com.example.jwtauth.model.User;
import com.example.jwtauth.repository.RoleRepository;
import com.example.jwtauth.repository.UserRepository;
import com.example.jwtauth.security.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    public String getString() {
        return "Hello, World";
    }

    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public void createUser(@RequestBody SignUpRq signUpRq) {
        var password = passwordEncoder.encode(signUpRq.password());
        var user = roleRepository.findByName(Role.Name.USER)
                .map(role -> User.builder()
                        .email(signUpRq.email())
                        .password(password.getBytes())
                        .username(signUpRq.username())
                        .roles(Set.of(role))
                        .build())
                        .orElseThrow(IllegalArgumentException::new);
        userRepository.save(user);
    }

    @PostMapping("/signin")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("permitAll()")
    public Object login(@RequestBody SignInRq signInRq) {
        try {
            var authentication = new UsernamePasswordAuthenticationToken(signInRq.username(), signInRq.password());
            authenticationManager.authenticate(authentication);
        } catch (AuthenticationException e) {
            throw new UsernamePasswordNotExistException("Invalid username or password");
        }

        var user = userRepository.findByUsername(signInRq.username())
                .orElseThrow(IllegalArgumentException::new);

        var username = user.getUsername();
        var roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        return Map.of("username", username,
                "roles", roles,
                "access_token", jwtProvider.generateToken(username, user.getRoles()));
    }

}
