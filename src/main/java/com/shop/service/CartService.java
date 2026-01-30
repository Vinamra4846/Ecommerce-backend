package com.shop.service;

import com.shop.exception.ProductException;
import com.shop.modal.Cart;
import com.shop.modal.CartItem;
import com.shop.modal.User;
import com.shop.request.AddItemRequest;

public interface CartService {
	
	public Cart createCart(User user);
	
	public CartItem addCartItem(Long userId,AddItemRequest req) throws ProductException;
	
	public Cart findUserCart(Long userId);

}
