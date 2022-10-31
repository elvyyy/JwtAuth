package com.example.jwtauth.model;

import lombok.*;

import javax.persistence.*;
import java.util.Set;

@Table(name = "users")
@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;
    private String username;
    private String email;

    @Column(length = 60)
    private byte[] password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "users_to_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;

}
