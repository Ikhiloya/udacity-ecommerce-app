package com.example.demo.controller;

import com.example.demo.TestUtil;
import com.example.demo.controllers.CartController;
import com.example.demo.controllers.UserController;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import com.example.demo.model.requests.ModifyCartRequest;
import org.assertj.core.util.Lists;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.math.BigDecimal;
import java.util.Optional;

import static com.example.demo.TestUtil.*;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.util.AssertionErrors.assertTrue;

public class CartControllerTest {
    private UserController userController;
    private CartController cartController;
    private UserRepository userRepo = mock(UserRepository.class);
    private CartRepository cartRepo = mock(CartRepository.class);
    private ItemRepository itemRepo = mock(ItemRepository.class);
    private BCryptPasswordEncoder encoder = mock(BCryptPasswordEncoder.class);

    @Before
    public void setUp() {
        userController = new UserController();
        TestUtil.injectObject(userController, "userRepository", userRepo);
        TestUtil.injectObject(userController, "cartRepository", cartRepo);
        TestUtil.injectObject(userController, "bCryptPasswordEncoder", encoder);

        cartController = new CartController();
        TestUtil.injectObject(cartController, "userRepository", userRepo);
        TestUtil.injectObject(cartController, "cartRepository", cartRepo);
        TestUtil.injectObject(cartController, "itemRepository", itemRepo);

        //mocks
        when(encoder.encode("testPassword")).thenReturn("passwdhash");
        when(userRepo.findByUsername("test")).thenReturn(getUser());
        when(itemRepo.findById(1L)).thenReturn(Optional.of(getItem()));
        when(cartRepo.save(new Cart())).thenReturn(getCart());
    }


    @Test
    public void test_add_to_cart_happy_path() {
        CreateUserRequest c = getCreateUserRequest();
        ResponseEntity<User> resp = userController.createUser(c);
        assertNotNull(resp);
        assertEquals(200, resp.getStatusCodeValue());
        User u = resp.getBody();
        assertNotNull(u);


        ResponseEntity<Cart> response = cartController.addTocart(getCartRequest(u.getUsername()));
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Cart c1 = response.getBody();
        assertNotNull(c1);
        assertNotNull(c1.getItems());
        assertEquals(1, c1.getItems().size());
    }


    @Test
    public void test_remove_from_cart_happy_path() {
        CreateUserRequest c = getCreateUserRequest();
        ResponseEntity<User> resp = userController.createUser(c);
        assertNotNull(resp);
        assertEquals(200, resp.getStatusCodeValue());
        User u = resp.getBody();
        assertNotNull(u);

        cartController.addTocart(getCartRequest(u.getUsername()));

        ResponseEntity<Cart> response = cartController.removeFromCart(getCartRequest(u.getUsername()));
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Cart c1 = response.getBody();
        assertNotNull(c1);
        assertNotNull(c1.getItems());
        assertEquals(0, c1.getItems().size());
    }


}
