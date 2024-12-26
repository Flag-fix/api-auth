package br.com.auth.api.services.impl;

import br.com.auth.api.entities.User;
import br.com.auth.api.entities.dto.CreateUserDto;
import br.com.auth.api.exception.ApiException;
import br.com.auth.api.repository.RoleRepository;
import br.com.auth.api.repository.UserRepository;
import br.com.auth.api.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Set;

@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    public void createUser(CreateUserDto dto) {
        var userFromDb = userRepository.findByUsername(dto.username());
        if (userFromDb.isPresent()) {
            throw new ApiException("User already exists", HttpStatus.UNPROCESSABLE_ENTITY);
        }

        var basicRole = roleRepository.findByName("BASIC");

        var user = new User();
        user.setUsername(dto.username());
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setRoles(Set.of(basicRole));

        userRepository.save(user);
    }

    @Override
    public void updateUser(String id, CreateUserDto dto) {
        var user = userRepository.findById(id)
                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND));

        userRepository.findByUsername(dto.username()).ifPresent(existingUser -> {
            if (!existingUser.getId().equals(user.getId())) {
                throw new ApiException("Username already in use", HttpStatus.UNPROCESSABLE_ENTITY);
            }
        });

        user.setUsername(dto.username());

        userRepository.save(user);
    }

    @Override
    public List<User> listUsers() {
        return userRepository.findAll();
    }

    @Override
    public void deleteUser(String id) {
        var user = userRepository.findById(id)
                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND));

        var currentAdmin = getCurrentAdmin();
        if (user.getId().equals(currentAdmin.getId())) {
            throw new ApiException("You cannot delete yourself", HttpStatus.FORBIDDEN);
        }

        userRepository.delete(user);
    }

    private User getCurrentAdmin() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        return userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new ApiException("Admin user not found", HttpStatus.INTERNAL_SERVER_ERROR));
    }


}
