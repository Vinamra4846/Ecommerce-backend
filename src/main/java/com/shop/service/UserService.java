package com.shop.service;

import java.util.List;

import com.shop.exception.UserException;
import com.shop.modal.User;

public interface UserService {
	
	public User findUserById(Long userId) throws UserException;
	
	public User findUserProfileByJwt(String jwt) throws UserException;
	
	public List<User> findAllUsers();

}
