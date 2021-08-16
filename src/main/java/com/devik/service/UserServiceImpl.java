package com.devik.service;

import com.devik.entity.Role;
import com.devik.entity.User;
import com.devik.repository.RoleRepository;
import com.devik.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUserName(username).orElseThrow();
    }

    @Override
    public User saveUser(User user) {
        return userRepository.save(user);
    }

    @Override
    public User getUser(String username) {
        return userRepository.findByUserName(username).orElseThrow();
    }

    @Override
    public Role saveRole(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public User addRoleToUser(String username, String rolename) {
        User user = userRepository.findByUserName(username).orElseThrow();
        Role role = roleRepository.findByName(rolename).orElseThrow();
        user.getRoles().add(role);
        return user;
    }

    @Override
    public Page<User> getAllUser(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

}
