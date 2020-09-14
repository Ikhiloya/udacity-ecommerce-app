package com.example.demo.controller;

import com.example.demo.TestUtil;
import com.example.demo.controllers.CartController;
import com.example.demo.controllers.OrderController;
import com.example.demo.controllers.UserController;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.OrderRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import org.aspectj.weaver.ast.Or;
import org.assertj.core.util.Lists;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.criteria.Order;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import static com.example.demo.TestUtil.*;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OrderControllerTest {
    private UserController userController;
    private CartController cartController;
    private OrderController orderController;
    private UserRepository userRepo = mock(UserRepository.class);
    private CartRepository cartRepo = mock(CartRepository.class);
    private OrderRepository orderRepo = mock(OrderRepository.class);
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


        orderController = new OrderController();
        TestUtil.injectObject(orderController, "userRepository", userRepo);
        TestUtil.injectObject(orderController, "orderRepository", orderRepo);

        //mocks
        when(encoder.encode("testPassword")).thenReturn("passwdhash");
        when(userRepo.findByUsername("test")).thenReturn(getUserWithCart());
        when(cartRepo.save(new Cart())).thenReturn(getCart());
        when(orderRepo.save(new UserOrder())).thenReturn(getUserOrder());
        when(orderRepo.findByUser(new User())).thenReturn(getUserOrders());
    }


    @Test
    public void test_submit_user_order_happy_path() {
        CreateUserRequest c = getCreateUserRequest();
        ResponseEntity<User> resp = userController.createUser(c);
        assertNotNull(resp);
        assertEquals(200, resp.getStatusCodeValue());
        User u = resp.getBody();
        assertNotNull(u);
        ResponseEntity<UserOrder> response = orderController.submitUserOrder(u.getUsername());
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        UserOrder userOrder = response.getBody();
        assertNotNull(userOrder);
        assertNotNull(userOrder.getItems());
        assertEquals(2, userOrder.getItems().size());
    }


    @Test
    public void test_get_orders_for_user_happy_path() {
        CreateUserRequest c = getCreateUserRequest();
        ResponseEntity<User> resp = userController.createUser(c);
        assertNotNull(resp);
        assertEquals(200, resp.getStatusCodeValue());
        User u = resp.getBody();
        assertNotNull(u);

        ResponseEntity<List<UserOrder>> response = orderController.getOrdersForUser(u.getUsername());
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        List<UserOrder> userOrders = response.getBody();
        assertNotNull(userOrders);
//        assertEquals(1, userOrders.size());
    }


}
