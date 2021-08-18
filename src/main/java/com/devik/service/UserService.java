package com.devik.service;

import com.devik.entity.Role;
import com.devik.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface UserService {
    User saveUser(User user);

    User getUser(String username);

    Role saveRole(Role role);

    User addRoleToUser(String username, String rolename);

    Page<User> getAllUser(Pageable pageable);
}
