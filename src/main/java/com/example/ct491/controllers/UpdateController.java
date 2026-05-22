package com.example.ct491.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import jakarta.servlet.http.HttpSession;
import java.util.Map;

@Controller
public class UpdateController {
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
    @GetMapping("/server/update")
    public String handleServerRequest(
        @RequestParam("host") String host, HttpSession session, Model model) {
        Object user = session.getAttribute("user");
        if (user == null || !(user instanceof Map)) {
            return "redirect:/";
        }
        Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
        model.addAttribute("server", server);
        return "update-server";
    }
    @PostMapping("/server/update")
public String handleUpdateServer(
    @RequestParam("originalHost") String originalHost,
    @RequestParam("username") String username,
    @RequestParam("post") int post,
    @RequestParam("password") String password,
    @RequestParam(value = "alias", required = false) String alias,
    RedirectAttributes redirectAttributes,
    HttpSession session) {

    Object user = session.getAttribute("user");
    if (user == null || !(user instanceof Map)) {
        return "redirect:/";
    }

    // Cập nhật thông tin server
    jdbcTemplate.update(
        "UPDATE servers SET user = ?,post = ?, password = ?, nickname = ? WHERE host = ?",
        username, post, password, alias, originalHost
    );

    // Redirect về trang server với host tương ứng
    redirectAttributes.addAttribute("host", originalHost);
    return "redirect:/server";
}
    
}
