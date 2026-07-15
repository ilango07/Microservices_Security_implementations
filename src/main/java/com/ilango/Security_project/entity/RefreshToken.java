package com.ilango.Security_project.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_refresh_token", columnList = "token"),
                @Index(name = "idx_refresh_user", columnList = "user_id")
        }
)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Random UUID
     */
    @Column(nullable = false, unique = true, length = 512)
    private String token;

    /**
     * Owner
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    /**
     * Expiry
     */
    @Column(nullable = false)
    private LocalDateTime expiryDate;

    /**
     * Logout / Rotation
     */
    @Column(nullable = false)
    private boolean revoked;

    /**
     * Reuse detection
     */
    @Column(nullable = false)
    private boolean expired;

    /**
     * Device Information
     */
    private String deviceName;

    private String ipAddress;

    @Column(length = 1000)
    private String userAgent;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}