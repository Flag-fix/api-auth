package br.com.auth.api.services.impl;

import br.com.auth.api.entities.RefreshToken;
import br.com.auth.api.entities.Role;
import br.com.auth.api.entities.User;
import br.com.auth.api.exception.ApiException;
import br.com.auth.api.repository.RefreshTokenRepository;
import br.com.auth.api.repository.UserRepository;
import br.com.auth.api.services.AuthService;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);


    @Override
    public String login(String username, String password) {
        logger.info("Login attempt for user: {}", username);
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isEmpty() || !passwordEncoder.matches(password, user.get().getPassword())) {
            throw new BadCredentialsException("Invalid username or password!");
        }

        User validUser = user.get();
        return generateToken(validUser);
    }

    @Override
    public String generateToken(User user) {
        var now = Instant.now();
        var expiresIn = 900L;

        var scopes = user.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.joining(" "));

        var claims = JwtClaimsSet.builder()
                .issuer("auth")
                .subject(user.getId())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresIn))
                .claim("roles", user.getRoles().stream().map(Role::getName).toList())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    @Override
    public String generateRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND));

        long activeTokens = refreshTokenRepository.countByUserAndRevokedIsFalse(user);
        if (activeTokens >= 5) {
            throw new ApiException("Too many active sessions", HttpStatus.FORBIDDEN);
        }

        String token = UUID.randomUUID().toString();
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setRefreshToken(token);
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plus(7, ChronoUnit.DAYS));

        refreshTokenRepository.save(refreshToken);
        return token;
    }


    @Override
    public String refreshToken(String refreshToken) {
        logger.info("Refresh token attempt: {}", refreshToken);
        RefreshToken token = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new ApiException("Invalid refresh token", HttpStatus.UNAUTHORIZED));

        if (token.isExpired()) {
            throw new ApiException("Refresh token expired", HttpStatus.UNAUTHORIZED);
        }
        token.setRevoked(true);
        refreshTokenRepository.save(token);

        String newRefreshToken = generateRefreshToken(token.getUser().getUsername());

        return generateToken(token.getUser());
    }

    @Override
    public void logout(String refreshToken) {
        logger.info("Logout for token: {}", refreshToken);
        RefreshToken token = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new ApiException("Invalid refresh token", HttpStatus.UNAUTHORIZED));
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }


}
