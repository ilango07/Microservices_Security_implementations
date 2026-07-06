package com.ilango.Security_project.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(
        name = "users",
        indexes = {
                @Index(
                        name = "idx_user_email",
                        columnList = "email"
                )
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(
            strategy = GenerationType.IDENTITY
    )
    private Long id;


    @Column(
            nullable = false,
            unique = true
    )
    private String email;


    /*
       LOCAL user:
       password = BCrypt password

       GOOGLE user:
       password = null
    */
    @Column(
            nullable = false
    )
    private String password;


    @Column(nullable = false)
    private AuthProvider provider;



    /*
      ID received from OAuth provider
      Example:
      Google user id
    */
    private String providerId;



    /*
       Email verification status
    */
    @Column(nullable = false)
    private boolean enabled;


    @Enumerated(EnumType.STRING)
    @Column(
            nullable = false
    )
    private Role role;



    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // ============================================================
    //  UserDetails Methods (Spring Security)
    // ============================================================

    /**
     * Returns the authorities/roles granted to the user.
     * Spring Security uses this for authorization.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Convert the Role enum to Spring Security's GrantedAuthority
        // Prefix with "ROLE_" as Spring Security expects
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
        // Examples:
        // ROLE_USER, ROLE_ADMIN, ROLE_MANAGER
    }

    /**
     * Returns the username used for authentication.
     * We use email as the username.
     */
    @Override
    public String getUsername() {
        return email;
    }

    /**
     * Returns the password used for authentication.
     * This should be the BCrypt hashed password.
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Indicates whether the user's account has expired.
     * true = account is valid (not expired)
     * false = account is expired
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked.
     * true = account is not locked
     * false = account is locked
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) has expired.
     * true = credentials are valid (not expired)
     * false = credentials are expired
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is enabled or disabled.
     * true = account is enabled (verified)
     * false = account is disabled (not verified)
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }
}