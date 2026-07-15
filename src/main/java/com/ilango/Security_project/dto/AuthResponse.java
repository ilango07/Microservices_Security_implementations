package com.ilango.Security_project.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private Long userId;

    private String email;

    private String role;

    private String accessToken;

    private String refreshToken;

    @Builder.Default
    private String tokenType="Bearer";      // Bearer

    private long expiresIn;         // seconds until access token expires
}