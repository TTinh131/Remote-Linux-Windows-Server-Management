package com.example.ct491.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@Controller
public class HomeController {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @GetMapping("/")
    public String index() {
        return "index"; 
    }// Xử lý đăng nhập
    @PostMapping("/home")
    public String login(@RequestParam String email, @RequestParam String password, Model model, HttpSession session) {
        if (email.isEmpty() || password.isEmpty()) {
            model.addAttribute("error", "Email và mật khẩu không được để trống!");
            return "index";
        }
        try {
            String sql = "SELECT * FROM users WHERE Email = ? AND Password = ?";
            Map<String, Object> user = jdbcTemplate.queryForMap(sql, email, password);
            // Lưu thông tin người dùng vào Session
            session.setAttribute("user", user);
            return "redirect:/home";
        } catch (Exception e) {
            model.addAttribute("error", "Email hoặc mật khẩu không đúng!");
            return "index";
        }
    }
    @GetMapping("/home")
    public String home(HttpSession session, Model model) {
        if (session.getAttribute("user") == null) {
            System.out.println("User not logged in. Redirecting to index.");
            return "redirect:/";
        }
        Map<String, Object> user = (Map<String, Object>) session.getAttribute("user");
        model.addAttribute("user", user);
        // Lấy danh sách máy chủ từ cơ sở dữ liệu
        String sql = "SELECT * FROM servers";
        List<Map<String, Object>> servers = jdbcTemplate.queryForList(sql);
        model.addAttribute("servers", servers);
        return "home";
    }
    @PostMapping("/delete-server")
    @ResponseBody
    public Map<String, Boolean> deleteServer(@RequestBody Map<String, String> request) {
        String host = request.get("host");
        String sql = "DELETE FROM servers WHERE host = ?";
        int rowsAffected = jdbcTemplate.update(sql, host);
        return Collections.singletonMap("success", rowsAffected > 0);
    }
    @PostMapping("/logout")
    public String logout(HttpSession session) {
        // Xóa thông tin người dùng khỏi Session
        session.invalidate();
        return "redirect:/";
    }
    
}