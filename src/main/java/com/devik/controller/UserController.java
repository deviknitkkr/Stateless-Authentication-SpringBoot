package com.devik.controller;

import com.devik.entity.Role;
import com.devik.entity.User;
import com.devik.service.UserService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/user")
    public User addUser(@RequestBody User user){
        return userService.saveUser(user);
    }

    @GetMapping("/user/{username}")
    public User getUser(@PathVariable("username") String username){
        return userService.getUser(username);
    }

    @GetMapping("/users")
    public Page<User> getAllUser(Pageable pageable){
        return userService.getAllUser(pageable);
    }

    @PostMapping("/role")
    public Role addRole(@RequestBody Role role){
        return userService.saveRole(role);
    }

    @PostMapping("/role/addtouser")
    public User addRoleToUser(@RequestBody UserNameRoleName userNameRoleName){
        return userService.addRoleToUser(userNameRoleName.getUsername(),userNameRoleName.getRolename());
    }

}

@Data
@AllArgsConstructor
class UserNameRoleName{
    private String username;
    private String rolename;
}