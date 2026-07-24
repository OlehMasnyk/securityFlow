package com.example.orders.web;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrdersController {

    @GetMapping("/api/orders")
    public Map<String, Object> orders(@AuthenticationPrincipal Jwt jwt) {
        List<Map<String, Object>> orders = List.of(
                Map.of("id", "ORD-1001", "item", "Mechanical keyboard", "amount", 89.90),
                Map.of("id", "ORD-1002", "item", "27\" monitor", "amount", 259.00),
                Map.of("id", "ORD-1003", "item", "USB-C hub", "amount", 39.50));

        return Map.of(
                "service", "orders-service",
                "owner", jwt.getSubject(),
                "scopes", jwt.getClaimAsStringList("scope"),
                "orders", orders);
    }
}
