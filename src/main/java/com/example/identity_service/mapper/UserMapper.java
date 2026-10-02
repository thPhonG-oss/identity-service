package com.example.identity_service.mapper;

import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.response.UserResponse;
import org.mapstruct.Mapper;

@Mapper
public interface UserMapper {
    public UserResponse toUserReponse(User user);
}
