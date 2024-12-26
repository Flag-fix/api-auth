package br.com.auth.api.entities.dto;

public record LoginResponse(String accessToken, String refreshToken, Long expiresIn) {}

