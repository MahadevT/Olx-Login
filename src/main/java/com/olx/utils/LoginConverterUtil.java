package com.olx.utils;

import com.olx.dto.User;
import com.olx.entity.UserEntity;
import org.modelmapper.ModelMapper;

import java.util.List;
import java.util.stream.Collectors;

public class LoginConverterUtil {

    public static User convertEntityToDto(ModelMapper modelMapper, UserEntity advertiseEntity) {
        return modelMapper.map(advertiseEntity, User.class);
    }

    public static UserEntity convertDtoToEntity(ModelMapper modelMapper, User advertise) {
        return modelMapper.map(advertise, UserEntity.class);
    }

    public static List<User> convertEntityToDto(ModelMapper modelMapper, List<UserEntity> advertiseEntityList) {
        return advertiseEntityList
                .stream()
                .map(advertiseEntity -> modelMapper.map(advertiseEntity, User.class))
                .collect(Collectors.toList());
    }

    public static List<UserEntity> convertDtoToEntity(ModelMapper modelMapper, List<User> advertiseList) {
        return advertiseList
                .stream()
                .map(advertise -> modelMapper.map(advertise, UserEntity.class))
                .collect(Collectors.toList());
    }
}
