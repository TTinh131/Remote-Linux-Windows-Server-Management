package com.example.ct491.controllers;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import com.example.ct491.ssh.SseNotifier;
import com.example.ct491.ssh.Connect;
import jakarta.servlet.http.HttpSession;

import java.util.HashMap;
import java.util.Map;

@Controller
public class ServerController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectProvider<Connect> connect;

    @ModelAttribute("user")
    public Map<String, Object> addUserToModel(HttpSession session) {
        Object userObj = session.getAttribute("user");
        if (userObj instanceof Map) {
            return (Map<String, Object>) userObj;
        }
        return null;
    }

    @GetMapping("/server")
    public String showServer(
            @ModelAttribute("host") String host, Model model, HttpSession session) {

        if (session.getAttribute("user") == null) {
            return "redirect:/";
        }

        try {
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            model.addAttribute("server", server);

            // Lấy map kết nối SSH đã tạo trong session
            Map<String, Connect> connectMap = (Map<String, Connect>) session.getAttribute("connectMap");
            if (connectMap == null) {
                connectMap = new HashMap<>();
                session.setAttribute("connectMap", connectMap);
            }

            Connect conn = connectMap.get(host);
            if (conn == null || !conn.isConnected()) {
                final Map<String, Connect> finalConnectMap = connectMap;
                // Tạo luồng riêng để kết nối SSH, không chặn main thread
                new Thread(() -> {
                    try {
                        Connect newConn = connect.getObject();
                        newConn.connect(host);
                        finalConnectMap.put(host, newConn);
                    } catch (Exception sshEx) {
                        System.err.println("SSH Error (background): " + sshEx.getMessage());
                    }
                }).start();
            }
            return "server";

        } catch (Exception e) {
            model.addAttribute("error", "Không tìm thấy server: " + e.getMessage());
            return "error";
        }
    }
}
