package com.shop.service;

import java.util.List;

import com.shop.exception.ProductException;
import com.shop.modal.Review;
import com.shop.modal.User;
import com.shop.request.ReviewRequest;

public interface ReviewService {

	public Review createReview(ReviewRequest req,User user) throws ProductException;
	
	public List<Review> getAllReview(Long productId);
	
	
}
