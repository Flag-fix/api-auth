package br.com.auth.api.repository;

import br.com.auth.api.entities.RefreshToken;
import br.com.auth.api.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);

    Long countByUserAndRevokedIsFalse(User user);
}
