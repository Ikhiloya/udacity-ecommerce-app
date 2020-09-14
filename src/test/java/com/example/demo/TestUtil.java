package com.example.demo;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.requests.CreateUserRequest;
import com.example.demo.model.requests.ModifyCartRequest;
import org.assertj.core.util.Lists;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.util.List;

public class TestUtil {
    public static void injectObject(Object target, String fieldName, Object toInject) {
        boolean wasPrivate = false;
        try {
            Field f = target.getClass().getDeclaredField(fieldName);
            if (!f.isAccessible()) {
                f.setAccessible(true);
                wasPrivate = true;
            }
            f.set(target, toInject);
            if (wasPrivate) {
                f.setAccessible(false);
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    public static CreateUserRequest getCreateUserRequest() {
        CreateUserRequest c = new CreateUserRequest();
        c.setUsername("test");
        c.setPassword("testPassword");
        c.setConfirmPassword("testPassword");
        return c;
    }

    public static User getUser() {
        User user = new User();
        user.setId(1);
        user.setUsername("test");
        user.setCart(new Cart());
        return user;
    }

    public static ModifyCartRequest getCartRequest(String username) {
        ModifyCartRequest request = new ModifyCartRequest();
        request.setUsername(username);
        request.setItemId(1);
        request.setQuantity(1);
        return request;
    }

    public static Cart getCart() {
        Cart cart = new Cart();
        cart.setItems(Lists.newArrayList(getItem()));
        cart.setUser(getUser());
        cart.setTotal(getItem().getPrice());
        return cart;
    }

    public static Item getItem() {
        Item item = new Item();
//        item.setId(1L);
        item.setName("Round Widget");
        item.setPrice(new BigDecimal(2.99));
        item.setDescription("A widget that is round");
        return item;
    }

    public static List<Item> getItems() {
        Item item1 = new Item();
        item1.setName("Round Widget");
        item1.setPrice(new BigDecimal(2.99));
        item1.setDescription("A widget that is round");

        Item item2 = new Item();
        item2.setName("Square Widget");
        item2.setPrice(new BigDecimal(1.99));
        item2.setDescription("A widget that is square");
        return Lists.newArrayList(item1, item2);
    }


    public static User getUserWithCart() {
        User user = new User();
        Cart cart = new Cart();
        cart.setItems(TestUtil.getItems());
        cart.setTotal(new BigDecimal(4.98));
        user.setCart(cart);
        return user;
    }


    public static UserOrder getUserOrder() {
        UserOrder userOrder = new UserOrder();
        userOrder.setItems(getItems());
        userOrder.setTotal(new BigDecimal(4.98));
        userOrder.setUser(getUser());
        return userOrder;
    }


    public static List<UserOrder> getUserOrders() {
        UserOrder userOrder1 = new UserOrder();
        userOrder1.setItems(getItems());
        userOrder1.setTotal(new BigDecimal(4.98));
        userOrder1.setUser(getUser());

        UserOrder userOrder2 = new UserOrder();
        userOrder2.setItems(getItems());
        userOrder2.setTotal(new BigDecimal(4.98));
        userOrder2.setUser(getUser());


        return Lists.newArrayList(userOrder1, userOrder2);
    }

}
