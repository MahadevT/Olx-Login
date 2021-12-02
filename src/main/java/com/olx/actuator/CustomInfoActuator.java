package com.olx.actuator;

import com.olx.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

@Component
public class CustomInfoActuator implements InfoContributor {

    @Autowired
    UserRepository userRepository;

    @Override
    public void contribute(Info.Builder builder) {
        builder
                .withDetail("total-registered-users", userRepository.count())
                .withDetail("active-login-count", 30)
                .build();
    }
}
