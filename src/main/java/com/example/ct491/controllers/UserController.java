package com.example.ct491.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import java.util.Map;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.ModelAttribute;

@Controller
public class UserController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @ModelAttribute("user")
    public Map<String, Object> addUserToModel(HttpSession session) {
        Object userObj = session.getAttribute("user");
        if (userObj instanceof Map) {
            return (Map<String, Object>) userObj;
        }
        return null; 
    }

    @GetMapping("/in4user")
    public String getUserInfo(HttpSession session, Model model) {
        Object userObj = session.getAttribute("user");
        if (userObj == null || !(userObj instanceof Map)) {
            return "redirect:/";
        }
        Map<String, Object> user = (Map<String, Object>) userObj;
        model.addAttribute("user", user);
        return "in4user";
    }
}