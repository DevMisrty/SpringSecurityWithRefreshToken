package com.example.springsecuritypact2.service;

import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UsersDetailsService implements UserDetailsService {

    private final UsersRepo usersRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Users> byUsername = usersRepo.findByUsername(username);
        if(byUsername.isEmpty())throw new UsernameNotFoundException("User Not Found");
        Users users = byUsername.get();
        return new User(users.getUsername(),users.getPassword(), List.of(new SimpleGrantedAuthority("ROLE_" + users.getRole())));
    }
}
