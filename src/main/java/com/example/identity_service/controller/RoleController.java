package com.example.identity_service.controller;

import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.service.RoleService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
public class RoleController extends BaseController{
    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @GetMapping
    public ResponseEntity<List<Role>> getAllRoles() {
        return new ResponseEntity<>(roleService.getAllRoles(), HttpStatus.OK);
    }

    @GetMapping("/{roleName}")
    public ResponseEntity<Role> getRoleByName(
          @PathVariable(name = "roleName") final RoleEnum roleName
    ) {
        return new ResponseEntity<>(roleService.getRoleByName(roleName), HttpStatus.OK);
    }
}
