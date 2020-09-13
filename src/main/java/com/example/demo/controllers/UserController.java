package com.example.demo.controllers;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private final Logger log = LoggerFactory.getLogger(UserController.class.getSimpleName());
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private CartRepository cartRepository;

    @GetMapping("/id/{id}")
    public ResponseEntity<User> findById(@PathVariable Long id) {
        log.info("action=FindUserByIdStart id={}", id);
        ResponseEntity<User> responseEntity = ResponseEntity.of(userRepository.findById(id));
        log.info("action=FindUserByIdCompleted id={}", id);
        return responseEntity;
    }

    @GetMapping("/{username}")
    public ResponseEntity<User> findByUserName(@PathVariable String username) {
        log.info("action=FindUserByUserNameStart id={}", username);
        User user = userRepository.findByUsername(username);
        ResponseEntity<User> responseEntity = user == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(user);
        log.info("action=FindUserByUserNameCompleted id={}", username);
        return responseEntity;
    }

    @PostMapping("/create")
    public ResponseEntity<User> createUser(@RequestBody CreateUserRequest createUserRequest) {
        log.info("action=CreateUserStart userName={}", createUserRequest.getUsername());
        User user = new User();
        user.setUsername(createUserRequest.getUsername());
        Cart cart = new Cart();
        cartRepository.save(cart);
        user.setCart(cart);

        if (createUserRequest.getPassword().length() < 7 ||
                !createUserRequest.getPassword().equals(createUserRequest.getConfirmPassword())) {
            log.error("action=CreateUser error with user password. Cannot create user {}", createUserRequest.getUsername());
            return ResponseEntity.badRequest().build();
        }
        user.setPassword(bCryptPasswordEncoder.encode(createUserRequest.getPassword()));
        userRepository.save(user);
        log.info("action=CreateUserComplete userName={}", createUserRequest.getUsername());

        return ResponseEntity.ok(user);
    }

}
