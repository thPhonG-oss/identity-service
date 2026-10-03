package com.example.identity_service.service.impl;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.repository.RoleRepository;
import com.example.identity_service.service.RoleService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Slf4j
public class RoleServiceImpl implements RoleService {
    private final RoleRepository roleRepository;

    public RoleServiceImpl(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public Role getRoleByName(final RoleEnum name) {

        return roleRepository.findByName(name).orElseThrow(() -> new GeneralException(ErrorCode.ROLE_NOT_FOUND));
    }

    @Override
    @Transactional(readOnly = true)
    public List<Role> getAllRoles() {
        List<Role> roles = roleRepository.findAll(Sort.by("id"));

        if (roles.isEmpty()) {
            log.warn("List of roles is empty");
        }

        return roles;
    }
}
