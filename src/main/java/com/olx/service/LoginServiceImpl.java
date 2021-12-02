package com.olx.service;

import com.olx.dto.User;
import com.olx.entity.AuthTokenDocument;
import com.olx.entity.UserEntity;
import com.olx.exception.InvalidAuthTokenException;
import com.olx.repository.AuthTokenRepository;
import com.olx.repository.UserRepository;
import com.olx.security.JwtUtil;
import com.olx.utils.ActiveStateEnum;
import com.olx.utils.LoginConverterUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class LoginServiceImpl implements LoginService {

	@Autowired
	UserRepository userRepository;

	@Autowired
	ModelMapper modelMapper;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	AuthTokenRepository authTokenRepository;

	@Autowired
	JwtUtil jwtUtil;

	@Override
	public boolean logout(String authToken) {
		boolean isValidtoken;
		String userName = "";
		try {
			String jwtToken = authToken.substring(7, authToken.length());
			userName = jwtUtil.extractUsername(jwtToken);
			UserEntity userEntity = userRepository.findByUsername(userName);
			if (userEntity == null) {
				throw new UsernameNotFoundException("User not found.");
			}
			List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
			grantedAuthorityList.add(new SimpleGrantedAuthority(userEntity.getRole()));
			UserDetails userDetails = new org.springframework.security.core.userdetails.User(userEntity.getUsername(),
					passwordEncoder.encode(userEntity.getPassword()), grantedAuthorityList);
			isValidtoken = jwtUtil.validateToken(jwtToken, userDetails);

			if (isValidtoken) {

				Optional<AuthTokenDocument> authTokenDocument = authTokenRepository.findByauthToken(jwtToken);
				if (authTokenDocument.isPresent()) {

					// authTokenRepository.save(authTokenDocument);// mongo save
					// userEntity.setActive(false);
					// userRepository.save(userEntity);

					throw new InvalidAuthTokenException();

				} else {

					AuthTokenDocument doc = new AuthTokenDocument();
					doc.setAuthToken(jwtToken);
					authTokenRepository.save(doc);
					userEntity.setActive(ActiveStateEnum.FALSE);
					userRepository.save(userEntity);
				}

			} else {
				throw new UsernameNotFoundException(userName);
			}

		} catch (Exception e) {
			return false;
		}
		return true;
	}

	@Override
	public User registerUser(User user) {
		try {
			user.setRole("ROLE_USER");
			return LoginConverterUtil.convertEntityToDto(modelMapper,
					userRepository.save(LoginConverterUtil.convertDtoToEntity(modelMapper, user)));
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public User getUserInfo(String username) {
		return LoginConverterUtil.convertEntityToDto(modelMapper, userRepository.findByUsername(username));
	}
}
