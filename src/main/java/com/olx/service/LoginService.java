package com.olx.service;

import com.olx.dto.User;

public interface LoginService {

    boolean logout(String username);

    User registerUser(User user);

    User getUserInfo(String username);
}
