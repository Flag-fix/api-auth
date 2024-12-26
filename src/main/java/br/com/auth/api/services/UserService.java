package br.com.auth.api.services;

import br.com.auth.api.entities.User;
import br.com.auth.api.entities.dto.CreateUserDto;

import java.util.List;

public interface UserService {
    void createUser(CreateUserDto dto);

    void updateUser(String id, CreateUserDto dto);

    List<User> listUsers();

    void deleteUser(String id);
}