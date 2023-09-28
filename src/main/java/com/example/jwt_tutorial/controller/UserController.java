package com.example.jwt_tutorial.controller;

import com.example.jwt_tutorial.dto.UserDto;
import com.example.jwt_tutorial.entity.User;
import com.example.jwt_tutorial.service.UserService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/test-redirect")
    public void testRedirect(HttpServletResponse response) throws IOException {
        response.sendRedirect("/api/user");
    }

    @PostMapping("/signup")
//    public ResponseEntity<UserDto> signup(
    public ResponseEntity<User> signup(
            @Valid @RequestBody UserDto userDto
    ) {
        return ResponseEntity.ok(userService.signup(userDto));
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
//    public ResponseEntity<UserDto> getMyUserInfo(HttpServletRequest request) {
    public ResponseEntity<User> getMyUserInfo(HttpServletRequest request) {
//        return ResponseEntity.ok(userService.getMyUserWithAuthorities());
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
//    public ResponseEntity<UserDto> getUserInfo(@PathVariable String username) {
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {
//        return ResponseEntity.ok(userService.getUserWithAuthorities(username));
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}