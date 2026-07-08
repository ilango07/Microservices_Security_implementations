package com.ilango.Security_project.repository;

import com.ilango.Security_project.entity.RefreshToken;
import com.ilango.Security_project.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findAllByUser(User user);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshToken rt
            SET rt.revoked = true,
                rt.expired = true
            WHERE rt.user = :user
              AND rt.revoked = false
            """)
    void revokeAllByUser(User user);

    @Modifying
    @Query("""
            DELETE FROM RefreshToken rt
            WHERE rt.expired = true
               OR rt.revoked = true
               OR rt.expiryDate < CURRENT_TIMESTAMP
            """)
    void deleteExpiredTokens();
}