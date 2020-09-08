package com.example.demo.controller;

import com.example.demo.TestUtil;
import com.example.demo.controllers.UserController;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static junit.framework.TestCase.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserControllerTest {
    private UserController userController;
    private UserRepository userRepo = mock(UserRepository.class);
    private CartRepository cartRepo = mock(CartRepository.class);
    private BCryptPasswordEncoder encoder = mock(BCryptPasswordEncoder.class);

    @Before
    public void setUp() {
        userController = new UserController();
        TestUtil.injectObject(userController, "userRepository", userRepo);
        TestUtil.injectObject(userController, "cartRepository", cartRepo);
        TestUtil.injectObject(userController, "bCryptPasswordEncoder", encoder);
    }


    @Test
    public void test_create_user_happy_path() {
        when(encoder.encode("testPassword")).thenReturn("passwdhash");
        CreateUserRequest c = getCreateUserRequest();

        ResponseEntity<User> response = userController.createUser(c);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        User u = response.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals("test", u.getUsername());
        assertEquals("passwdhash", u.getPassword());
    }


    @Test
    public void test_find_by_username_happy_path() {
        when(encoder.encode("testPassword")).thenReturn("passwdhash");
        when(userRepo.findByUsername("test")).thenReturn(getUser());
        CreateUserRequest c = getCreateUserRequest();
        ResponseEntity<User> resp = userController.createUser(c);
        assertNotNull(resp);
        assertEquals(200, resp.getStatusCodeValue());


        ResponseEntity<User> response = userController.findByUserName(c.getUsername());
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        User u = response.getBody();
        assertNotNull(u);
        assertEquals(c.getUsername(), u.getUsername());
    }

    @Test
    public void test_find_by_invalid_username_and_return_not_found() {
        ResponseEntity<User> response = userController.findByUserName("David");
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }


    @Test
    public void test_find_by_id_happy_path() {
        when(encoder.encode("testPassword")).thenReturn("passwdhash");
        when(userRepo.findById(0L)).thenReturn(Optional.of(getUser()));
        CreateUserRequest c = getCreateUserRequest();
        ResponseEntity<User> resp = userController.createUser(c);
        assertNotNull(resp);
        assertEquals(200, resp.getStatusCodeValue());
        User u = resp.getBody();
        assertNotNull(u);

        ResponseEntity<User> response = userController.findById(u.getId());
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        User u1 = response.getBody();
        assertNotNull(u1);
        assertEquals(c.getUsername(), u1.getUsername());
    }

    @Test
    public void test_find_by_invalid_id_and_return_not_found() {
        ResponseEntity<User> response = userController.findById(1L);
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    private CreateUserRequest getCreateUserRequest() {
        CreateUserRequest c = new CreateUserRequest();
        c.setUsername("test");
        c.setPassword("testPassword");
        c.setConfirmPassword("testPassword");
        return c;
    }

    private User getUser() {
        User user = new User();
        user.setUsername("test");
        return user;
    }
}
