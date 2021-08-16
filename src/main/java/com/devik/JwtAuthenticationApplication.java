package com.devik;

import com.devik.entity.Role;
import com.devik.entity.User;
import com.devik.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtAuthenticationApplication.class, args);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    CommandLineRunner commandLineRunner(UserService userService, PasswordEncoder encoder) {
        return args -> {
            userService.saveRole(new Role(null, "ROOT"));
            userService.saveRole(new Role(null, "ADMIN"));
            userService.saveRole(new Role(null, "MANAGER"));
            userService.saveRole(new Role(null, "USER"));

            userService.saveUser(new User(null, "name1 suffix1", "name1", encoder.encode("1234"), new ArrayList<>()));
            userService.saveUser(new User(null, "name2 suffix2", "name2", encoder.encode("1234"), new ArrayList<>()));
            userService.saveUser(new User(null, "name3 suffix3", "name3", encoder.encode("1234"), new ArrayList<>()));
            userService.saveUser(new User(null, "name4 suffix4", "name4", encoder.encode("1234"), new ArrayList<>()));

            userService.addRoleToUser("name1", "ADMIN");
            userService.addRoleToUser("name2", "MANAGER");
            userService.addRoleToUser("name1", "ROOT");
            userService.addRoleToUser("name3", "USER");
            userService.addRoleToUser("name4", "MANAGER");

        };
    }
}
