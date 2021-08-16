package com.devik.service;

import com.devik.entity.Role;
import com.devik.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface UserService {
    public User saveUser(User user);

    public User getUser(String username);

    public Role saveRole(Role role);

    public User addRoleToUser(String username, String rolename);

    public Page<User> getAllUser(Pageable pageable);
}
