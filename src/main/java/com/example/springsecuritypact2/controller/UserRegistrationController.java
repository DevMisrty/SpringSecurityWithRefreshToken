package com.example.springsecuritypact2.controller;

import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class UserRegistrationController {

    private final PasswordEncoder passwordEncoder;
    private final UsersRepo usersRepo;

    @PostMapping("/users")
    public String addUsers(@RequestBody Users users){
        String password = passwordEncoder.encode(users.getPassword());
        users.setPassword(password);
        users.setRole("user");
        usersRepo.save(users);
        return "Users have Successfully created";
    }

    @PostMapping("/admins")
    public String addAdmins(@RequestBody Users users){
        String password = passwordEncoder.encode(users.getPassword());
        users.setPassword(password);
        users.setRole("admin");
        usersRepo.save(users);
        return "Admin have Successfully created";
    }
}
