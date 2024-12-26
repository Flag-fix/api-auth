package br.com.auth.api.controller;

import br.com.auth.api.entities.dto.LoginRequest;
import br.com.auth.api.entities.dto.LoginResponse;
import br.com.auth.api.entities.dto.RefreshTokenDTO;
import br.com.auth.api.services.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class TokenController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        String accessToken = authService.login(loginRequest.username(), loginRequest.password());
        String refreshToken = authService.generateRefreshToken(loginRequest.username());
        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken, 600L));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@RequestBody RefreshTokenDTO refreshToken) {
        String accessToken = authService.refreshToken(refreshToken.refreshToken());
        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken.refreshToken(), 600L));
    }

    @PostMapping("/logoff")
    public ResponseEntity<Void> logout(@RequestBody RefreshTokenDTO refreshToken) {
        authService.logout(refreshToken.refreshToken());
        return ResponseEntity.ok().build();
    }
}
