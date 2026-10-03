package com.example.identity_service.service;

import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;

import java.util.List;
import java.util.Optional;

public interface RoleService {
    Role getRoleByName(final RoleEnum name);

    List<Role> getAllRoles();
}
