package com.example.ct491.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ui.Model;
import java.util.Map;
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.HashMap;

import jakarta.servlet.http.HttpSession;

@Controller
public class AddserverController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/home/addserver")
    public String addServer(HttpSession session, Model model) {
        if (session.getAttribute("user") == null) {
            System.out.println("User not logged in. Redirecting to index.");
            return "redirect:/";
        }
        // Lấy thông tin người dùng từ session
        Map<String, Object> user = (Map<String, Object>) session.getAttribute("user");
        model.addAttribute("user", user);
        return "add-server";
    }

    @PostMapping("/home/addserver")
    @ResponseBody
    public Map<String, String> handleAddServerAjax(
            @RequestParam("IPaddress") String host,
            @RequestParam("username") String user,
            @RequestParam("port") int post,
            @RequestParam("password") String password,
            @RequestParam(value = "alias", required = false) String nickname) {

        Map<String, String> response = new HashMap<>();
        // Kiểm tra xem host đã tồn tại trong cơ sở dữ liệu chưa
        String checkQuery = "SELECT COUNT(*) FROM servers WHERE host = ?";
        Integer count = jdbcTemplate.queryForObject(checkQuery, new Object[]{host}, Integer.class);

        if (count > 0) {
            response.put("status", "error");
            response.put("message", "Địa chỉ IP đã tồn tại trong cơ sở dữ liệu!");
            return response;
        }
        // Thêm server mới vào cơ sở dữ liệu
        String insertQuery = "INSERT INTO servers (host, user, post, password, nickname) VALUES (?, ?, ?, ?, ?)";
        jdbcTemplate.update(insertQuery, host, user, post, password, nickname);

        response.put("status", "success");
        response.put("message", "Thêm server thành công!");
        return response;
    }
}