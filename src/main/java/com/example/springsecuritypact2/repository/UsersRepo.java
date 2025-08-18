package com.example.springsecuritypact2.repository;

import com.example.springsecuritypact2.model.Users;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UsersRepo extends CrudRepository<Users,Long> {
    Optional<Users> findByUsername(String username);
}
