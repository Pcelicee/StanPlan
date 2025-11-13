package com.pcelice.backend.controller;

import com.pcelice.backend.entities.CoOwner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@Profile("security")
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping
    public Map<String, Object> getCurrentUser(@AuthenticationPrincipal Object principal) {
        String name = null;

        if (principal instanceof UserDetails ud) {
            name = ud.getUsername();
        } else if (principal instanceof OAuth2User oau) {
            name = oau.getAttribute("name");
            if (name == null) name = oau.getAttribute("login");
        } else if (principal instanceof Principal p) {
            name = p.getName();
        }

        return Map.of("name", name);
    }
}

