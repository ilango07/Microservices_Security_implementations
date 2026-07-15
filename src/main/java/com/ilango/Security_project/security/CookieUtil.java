package com.ilango.Security_project.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    // ============================================================
    // Access Token Cookie
    // ============================================================
    public void createAccessTokenCookie(
            String accessToken,
            long maxAge,
            HttpServletResponse response
    ) {

        ResponseCookie cookie = ResponseCookie.from("accessToken", accessToken)
                .httpOnly(true)
                .secure(false)          // true in production (HTTPS)
                .path("/")
                .sameSite("Strict")
                .maxAge(maxAge)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // ============================================================
    // Refresh Token Cookie
    // ============================================================
    public void createRefreshTokenCookie(
            String refreshToken,
            long maxAge,
            HttpServletResponse response
    ) {

        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .sameSite("Strict")
                .maxAge(maxAge)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // ============================================================
    // Clear Access Token Cookie
    // ============================================================
    public void clearAccessTokenCookie(HttpServletResponse response) {

        ResponseCookie cookie = ResponseCookie.from("accessToken", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .sameSite("Strict")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // ============================================================
    // Clear Refresh Token Cookie
    // ============================================================
    public void clearRefreshTokenCookie(HttpServletResponse response) {

        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .sameSite("Strict")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // ============================================================
    // Clear Both Cookies
    // ============================================================
    public void clearCookies(HttpServletResponse response) {

        clearAccessTokenCookie(response);
        clearRefreshTokenCookie(response);
    }
}