package com.example.identity_service.mapper;

import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.response.UserDtoResponse;
import org.mapstruct.Mapper;

@Mapper
public interface UserMapper {
    public UserDtoResponse toUserReponse(User user);
}
