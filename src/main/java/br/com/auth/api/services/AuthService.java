package br.com.auth.api.services;

import br.com.auth.api.entities.User;

public interface AuthService {
    String login(String username, String password);
    String generateToken(User user);
    String refreshToken(String refreshToken);
    String generateRefreshToken(String username);
    void logout(String refreshToken);
}
