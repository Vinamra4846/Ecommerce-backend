package com.shop.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.shop.modal.OrderItem;

public interface OrderItemRepository extends JpaRepository<OrderItem, Long> {

}
