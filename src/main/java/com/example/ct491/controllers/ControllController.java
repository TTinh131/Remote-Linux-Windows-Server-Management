package com.example.ct491.controllers;

import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.ct491.ssh.Connect;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/controll-btn")
public class ControllController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectProvider<Connect> connect;

    @PostMapping("/restart")
    public String restart(@RequestParam("host") String host, HttpSession session) {
        return controllbtn(host, "restart", session);
    }

    @PostMapping("/shutdown")
    public String shutdown(@RequestParam("host") String host, HttpSession session) {
        return controllbtn(host, "shutdown", session);
    }

    private String controllbtn(String host, String action, HttpSession session) {
        try {
            // Kiểm tra và lấy connectMap từ session
            Map<String, Connect> sessionConnects = (Map<String, Connect>) session.getAttribute("connectMap");
            if (sessionConnects == null) {
                return "Session không chứa kết nối SSH. Vui lòng kết nối SSH trước.";
            }

            Connect conn = sessionConnects.get(host);
            if (conn == null) {
                return "Không tìm thấy kết nối SSH cho host: " + host;
            }

            if (!conn.isConnected()) {
                return "Kết nối SSH đến host " + host + " đã bị ngắt.";
            }

            // Truy vấn thông tin máy chủ từ cơ sở dữ liệu
            Map<String, Object> server;
            try {
                server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            } catch (Exception e) {
                return "Không tìm thấy thông tin máy chủ trong database với host: " + host;
            }

            String osType = (String) server.get("os_type");
            String password = (String) server.get("password");

            // Tạo lệnh tuỳ thuộc OS và hành động
            String cmd;
            if ("restart".equalsIgnoreCase(action)) {
                cmd = osType.equalsIgnoreCase("windows") ? "shutdown -r -t 0" : "echo '" + password + "' |sudo -S reboot";
            } else if ("shutdown".equalsIgnoreCase(action)) {
                cmd = osType.equalsIgnoreCase("windows") ? "shutdown -s -t 0" : "echo '" + password + "' |sudo -S shutdown -h now";
            } else {
                return "Lệnh không hợp lệ.";
            }

            // Gửi lệnh qua SSH
            conn.CommandExec(cmd);

            return "Đã gửi lệnh đến host: " + host;
        } catch (Exception e) {
            e.printStackTrace(); // Ghi log lỗi để dễ debug nếu chạy trên server
            return "Lỗi thực thi: " + e.getMessage();
        }
    }
}
