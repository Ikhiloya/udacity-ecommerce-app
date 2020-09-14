package com.example.demo.controller;

import com.example.demo.TestUtil;
import com.example.demo.controllers.ItemController;
import com.example.demo.controllers.UserController;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import org.assertj.core.util.Lists;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import static com.example.demo.TestUtil.*;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ItemControllerTest {
    private UserController userController;
    private ItemController itemController;
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

        itemController = new ItemController();
        TestUtil.injectObject(itemController, "itemRepository", itemRepo);


        //mocks
        when(encoder.encode("testPassword")).thenReturn("passwdhash");
        when(userRepo.findByUsername("test")).thenReturn(getUser());
        when(itemRepo.findById(1L)).thenReturn(Optional.of(getItem()));
        when(cartRepo.save(new Cart())).thenReturn(getCart());
        when(itemRepo.findAll()).thenReturn(getItems());
        when(itemRepo.findByName("Round Widget")).thenReturn(Lists.newArrayList(getItem()));
    }


    @Test
    public void test_get_items_happy_path() {
        ResponseEntity<List<Item>> response = itemController.getItems();
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        List<Item> items = response.getBody();
        assertNotNull(items);
        assertEquals(2, items.size());
    }

    @Test
    public void test_get_item_by_id_happy_path() {
        ResponseEntity<Item> response = itemController.getItemById(1L);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Item item = response.getBody();
        assertNotNull(item);
        assertEquals("Round Widget", item.getName());
        assertEquals(new BigDecimal(2.99), item.getPrice());
    }

    @Test
    public void test_get_items_by_id_happy_path() {
        ResponseEntity<List<Item>> response = itemController.getItemsByName("Round Widget");
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        List<Item> items = response.getBody();
        assertNotNull(items);
        assertEquals(1, items.size());
    }

}
