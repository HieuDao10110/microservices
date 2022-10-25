package com.example.authservice.controller;

import com.example.authservice.Service.JwtBlackListService;
import com.example.authservice.config.UserRequestScopedBean;
import com.example.authservice.security.TokenGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/auth/user")
@Slf4j
public class UserController {
    @Autowired
    JwtBlackListService blackListingService;
    @Autowired
    UserRequestScopedBean userRequestScopedBean;

    @PostMapping(value = "/login")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    public ResponseEntity login(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean hasUserRole = authentication.getAuthorities().stream()
                .anyMatch(r -> r.getAuthority().equals("ROLE_USER"));
        boolean hasAdminRole = authentication.getAuthorities().stream()
                .anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"));
        if(hasUserRole){
            return ResponseEntity.ok("user");
        }
        if(hasAdminRole){
            return ResponseEntity.ok("admin");
        }
        return ResponseEntity.ok("unknow");
    }

    @PostMapping(value = "/logout")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    public ResponseEntity logout() {
        blackListingService.blackListJwt(userRequestScopedBean.getJwt());
        return ResponseEntity.ok("logout success");
    }
}

