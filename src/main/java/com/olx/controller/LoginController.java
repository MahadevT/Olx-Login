package com.olx.controller;

import com.olx.dto.AuthenticationRequest;
import com.olx.dto.User;
import com.olx.entity.AuthTokenDocument;
import com.olx.exception.InvalidAuthTokenException;
import com.olx.repository.AuthTokenRepository;
import com.olx.security.JwtUtil;
import com.olx.service.LoginService;
import io.swagger.annotations.ApiOperation;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/olx/user")
public class LoginController {

	@Autowired
	LoginService loginService;

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	AuthTokenRepository authTokenRepository;

	@Autowired
	JwtUtil jwtUtil;

	@Autowired
	UserDetailsService userDetailsService;

	// 1
	@ApiOperation(value = "Authenticate user in the application.")
	@PostMapping(value = "/authenticate", consumes = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE }, produces = { MediaType.APPLICATION_JSON_VALUE,
					MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> login(@RequestBody AuthenticationRequest authenticationRequest) {
		try {

			Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(), authenticationRequest.getPassword()));
			if (authentication.isAuthenticated()) {
				String token = jwtUtil
						.generateToken(userDetailsService.loadUserByUsername(authenticationRequest.getUsername()));
				return new ResponseEntity<>(token, HttpStatus.OK);
			} else {
				return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
			}
		} catch (BadCredentialsException e) {
			return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}

	// 2
	@ApiOperation(value = "Logs out authenticated user from the application.")
	@DeleteMapping(value = "/logout")
	public ResponseEntity<Boolean> logout(@RequestHeader("Authorization") String authToken) {

		ResponseEntity<Boolean> validTokenResponse = validateToken(authToken);
		if (Boolean.TRUE.equals(validTokenResponse.getBody())) {
			ResponseEntity<String> usernameResponse = getUsername(authToken);
			return new ResponseEntity<>(loginService.logout(authToken), HttpStatus.OK);
		} else {
			return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
		}
	}

	// 3
	@ApiOperation(value = "Register a user in the application.")
	@PostMapping(value = "/", consumes = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE }, produces = { MediaType.APPLICATION_JSON_VALUE,
					MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<Object> registerUser(@RequestBody User user) {
		User newUser = loginService.registerUser(user);
		if (newUser != null) {
			return new ResponseEntity<>(newUser, HttpStatus.CREATED);
		} else {
			return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
		}
	}

	// 4
	@ApiOperation(value = "Get information of a user from the application.")
	@GetMapping(value = "/", produces = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<Object> getUserInfo(@RequestHeader("Authorization") String authToken) {

		ResponseEntity<Boolean> validTokenResponse = validateToken(authToken);
		if (Boolean.TRUE.equals(validTokenResponse.getBody())) {
			ResponseEntity<String> usernameResponse = getUsername(authToken);
			return new ResponseEntity<>(loginService.getUserInfo(usernameResponse.getBody()), HttpStatus.OK);
		} else {
			return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
		}
	}

	// Validate Token

	@ApiOperation(value = "Validate Token")
	@GetMapping(value = "/validate/token")
	public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization") String authToken) {
		Boolean isValidToken = false;
		String token = "";
		try {
			token = authToken.replace("Bearer ", "");
			UserDetails userDetails = userDetailsService.loadUserByUsername(jwtUtil.extractUsername(token));
			isValidToken = jwtUtil.validateToken(token, userDetails);
			if (isValidToken) {				
				Optional<AuthTokenDocument> authTokenDocument = authTokenRepository.findByauthToken(token);
				if (authTokenDocument.isPresent()) {
					AuthTokenDocument doc = authTokenDocument.get();

					if (doc.getAuthToken().equals(token)) {
						isValidToken = false;
						throw new InvalidAuthTokenException();

					}
				}
			}
		} catch (Exception e) {
			return new ResponseEntity<>(false, HttpStatus.BAD_REQUEST);
		}
		return new ResponseEntity(isValidToken, HttpStatus.OK);
	}

	// Get Username
	@ApiOperation(value = "To fetch Username")
	@GetMapping(value = "/name")
	public ResponseEntity<String> getUsername(@RequestHeader("Authorization") String authToken) {
		try {
			String token = authToken.replace("Bearer ", "");
			String username = jwtUtil.extractUsername(token);
			if (username.isEmpty()) {
				return new ResponseEntity<>("", HttpStatus.UNAUTHORIZED);
			}
			return new ResponseEntity<>(username, HttpStatus.OK);
		} catch (Exception e) {
			return new ResponseEntity<>("", HttpStatus.BAD_REQUEST);
		}
	}
}
