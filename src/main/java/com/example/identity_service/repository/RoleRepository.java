package com.example.identity_service.repository;

import java.util.Optional;

import com.example.identity_service.model.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;

import com.example.identity_service.model.Role;

public interface RoleRepository extends JpaRepository<Role, Short> {

    Optional<Role> findByName(RoleEnum roleEnum);
}
