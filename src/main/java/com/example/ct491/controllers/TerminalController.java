package com.example.ct491.controllers;

import com.example.ct491.ssh.Connect;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpSession;

import java.util.Map;
import java.util.List;

@Controller
@RequestMapping("/terminal")
public class TerminalController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectProvider<Connect> connect;

    //Gắn thông tin user từ session vào model
    @ModelAttribute("user")
    public Map<String, Object> addUserToModel(HttpSession session) {
        Object userObj = session.getAttribute("user");
        if (userObj instanceof Map) {
            return (Map<String, Object>) userObj;
        }
        return null;
    }

    @GetMapping
    public String showTerminal(@RequestParam String host, Model model, HttpSession session) throws InterruptedException {
        if (session.getAttribute("user") == null) {
            return "redirect:/";
        }

        try {
            //Lấy thông tin server từ DB
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            model.addAttribute("server", server); // sidebar-server cần biến này
            model.addAttribute("host", host);     // dùng cho JS
            // Lấy hoặc tạo Connect từ session
            Map<String, Connect> Connects = (Map<String, Connect>) session.getAttribute("connectMap");
            if (Connects == null) {
                Connects = new java.util.HashMap<>();
                session.setAttribute("connectMap", Connects);
            }
            Connect conn = Connects.get(host);
            if (conn == null) {
                conn = connect.getObject();
                conn.setOsType((String) server.get("os_type"));
                Connects.put(host, conn);
            }
            //Cố gắng kết nối tối đa 3 lần
            boolean connected = false;
            for (int i = 0; i < 3; i++) {
                try {
                    conn.connect(host);
                    conn.connectShell(); // khởi tạo shell channel
                    connected = conn.isConnected();
                    if (connected) {
                        break;
                    }
                } catch (Exception ignored) {
                }
                Thread.sleep(100);
            }
            if (!connected) {
                model.addAttribute("error", "Không thể kết nối sau 3 lần thử.");
                return "error";
            }
            return "terminal"; // render terminal.html
        } catch (Exception e) {
            model.addAttribute("error", "Không tìm thấy server hoặc lỗi khi kết nối SSH!");
            return "error";
        }
    }

    //AJAX thực thi lệnh
    @ResponseBody
    @GetMapping("/execute")
    public String execute(@RequestParam String host, @RequestParam String command, HttpSession session) {
        Map<String, Connect> Connects = (Map<String, Connect>) session.getAttribute("connectMap");
        if (Connects == null || !Connects.containsKey(host)) {
            return "Không có kết nối SSH hoặc máy offline.";
        }

        Connect conn = Connects.get(host);
        if (conn == null || !conn.isConnected()) {
            return "Không có kết nối SSH hoặc máy offline.";
        }

        try {
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            String osType = (String) server.get("os_type");
            String output;

            if (osType != null && "windows".equalsIgnoreCase(osType)) {
                output = conn.CommandExec(command);//cmd với quyền admin
            } else {
                output = conn.CommandShellLinux(List.of(command));
                // Loại bỏ "[?2004l"
                int idx = output.indexOf("[?2004l");
                if (idx != -1) {
                    output = output.substring(idx + "[?2004l".length());
                }
                // Xóa escape ANSI
                output = output.replaceAll("\u001B\\[[;\\d]*[ -/]*[@-~]", "");
                // Bỏ prompt shell nếu có
                String[] lines = output.split("\r?\n");
                if (lines.length > 1) {
                    output = String.join("\n", java.util.Arrays.copyOf(lines, lines.length - 1));
                }
            }
            return output.isEmpty() ? "(Không có kết quả)" : output;

        } catch (Exception e) {
            return "Lỗi khi thực thi lệnh: " + e.getMessage();
        }
    }
}
