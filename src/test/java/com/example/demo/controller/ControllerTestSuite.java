package com.example.demo.controller;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({UserControllerTest.class, CartControllerTest.class, ItemControllerTest.class, OrderControllerTest.class})
public class ControllerTestSuite {

    // intentionally empty - Test Suite Setup (annotations) is sufficient
}
