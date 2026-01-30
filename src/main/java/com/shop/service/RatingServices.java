package com.shop.service;

import java.util.List;

import com.shop.exception.ProductException;
import com.shop.modal.Rating;
import com.shop.modal.User;
import com.shop.request.RatingRequest;

public interface RatingServices {
	
	public Rating createRating(RatingRequest req,User user) throws ProductException;
	
	public List<Rating> getProductsRating(Long productId);

}
