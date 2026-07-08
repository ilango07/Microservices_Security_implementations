package com.ilango.Security_project.service;

import com.ilango.Security_project.entity.RefreshToken;
import com.ilango.Security_project.entity.User;
import com.ilango.Security_project.exception.ApiException;
import com.ilango.Security_project.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private final SecureRandom secureRandom = new SecureRandom();


    //Generates a secure random refresh token.

    private String generateRefreshTokenValue() {

        byte[] bytes = new byte[64];
        secureRandom.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }


     //Creates a refresh token after successful login.

    @Transactional
    public RefreshToken createRefreshToken(User user) {

        RefreshToken refreshToken = RefreshToken.builder()
                .token(generateRefreshTokenValue())
                .user(user)
                .expiryDate(LocalDateTime.now()
                        .plusSeconds(refreshTokenExpiration / 1000))
                .revoked(false)
                .expired(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }


     //Validates a refresh token.

    @Transactional
    public RefreshToken verifyRefreshToken(String token) {

        RefreshToken refreshToken = refreshTokenRepository
                .findByToken(token)
                .orElseThrow(() ->
                        new ApiException(
                                HttpStatus.UNAUTHORIZED,
                                "Invalid refresh token"
                        ));

        if (refreshToken.isRevoked()) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh token has been revoked"
            );
        }

        if (refreshToken.isExpired()) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh token has expired"
            );
        }

        if (refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {

            refreshToken.setExpired(true);

            refreshTokenRepository.save(refreshToken);

            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh token has expired"
            );
        }

        if (!refreshToken.getUser().isEnabled()) {

            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "User account is disabled"
            );
        }

        return refreshToken;
    }


     //Logout current device.

    @Transactional
    public void revokeRefreshToken(String token) {

        RefreshToken refreshToken = verifyRefreshToken(token);

        refreshToken.setRevoked(true);
        refreshToken.setExpired(true);

        refreshTokenRepository.save(refreshToken);
    }

       //Logout from all devices.

    @Transactional
    public void revokeAllRefreshTokens(User user) {

        refreshTokenRepository.revokeAllByUser(user);
    }


      //Refresh token rotation.

    @Transactional
    public RefreshToken rotateRefreshToken(String oldToken) {

        RefreshToken oldRefreshToken = verifyRefreshToken(oldToken);

        oldRefreshToken.setRevoked(true);
        oldRefreshToken.setExpired(true);

        refreshTokenRepository.save(oldRefreshToken);

        return createRefreshToken(oldRefreshToken.getUser());
    }


    //Cleanup revoked and expired tokens.

    @Transactional
    public void deleteExpiredTokens() {

        refreshTokenRepository.deleteExpiredTokens();
    }
}