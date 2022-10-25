package com.example.authservice.controller;

import com.example.authservice.dto.LoginDto;
import com.example.authservice.dto.SignUpDto;
import com.example.authservice.dto.TokenDto;
import com.example.authservice.model.User;
import com.example.authservice.security.JwtToUserConverter;
import com.example.authservice.security.TokenGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;

@RestController
@RequestMapping("/auth/guest")
public class AuthController {
    @Autowired
    UserDetailsManager userDetailsManager;

    @Autowired
    TokenGenerator tokenGenerator;

    @Autowired
    DaoAuthenticationProvider daoAuthenticationProvider;

    @Autowired
    @Qualifier("jwtRefreshTokenAuthProvider")
    JwtAuthenticationProvider refreshTokenAuthProvider;

    @Autowired
    JwtToUserConverter jwtToUserConverter;

    private static final Logger logger = LogManager.getLogger(AuthController.class);

    @GetMapping(value = "/")
    public String home() throws Exception{

//        logger.info("log4j2 ............................");
//        throw new Exception("Test log");

        return "auth-server";
    }

    @PostMapping(value = "/register")
    public ResponseEntity register(@RequestBody SignUpDto signupDTO){
        User user = new User(signupDTO.getUsername(), signupDTO.getPassword());
        userDetailsManager.createUser(user);
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(user, signupDTO.getPassword(), Collections.EMPTY_LIST);

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @CrossOrigin(origins = "http://localhost:4200")
    @PostMapping(value = "/login")
    public ResponseEntity login(@RequestBody LoginDto loginDto){
        Authentication authentication = daoAuthenticationProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(loginDto.getUsername(), loginDto.getPassword()));
        TokenDto token = tokenGenerator.createToken(authentication);
        String accessTokenKey = "access-token";
        String accessTokenValue = token.getAccessToken();

        String refreshTokenKey = "refresh-token";
        String refreshTokenValue = token.getRefreshToken();

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set(accessTokenKey, accessTokenValue);
        responseHeaders.set(refreshTokenKey, refreshTokenValue);

        return ResponseEntity.ok().headers(responseHeaders).body("");
    }

    @PostMapping("/token")
    public ResponseEntity token(@RequestBody TokenDto tokenDto) {
        Authentication authentication = refreshTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(tokenDto.getRefreshToken()));
        Jwt jwt = (Jwt) authentication.getCredentials();
        // check if present in db and not revoked, etc

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }
}
