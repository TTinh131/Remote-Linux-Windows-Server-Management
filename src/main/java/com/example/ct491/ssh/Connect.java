package com.example.ct491.ssh;

import com.jcraft.jsch.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
@Scope("prototype")
public class Connect {

    private Session session;
    private ChannelShell shellChannel;
    private InputStream in;
    private OutputStream out;
    private String osType;

    @Autowired
    private JdbcTemplate jdbc;

    public void connect(String host) throws Exception {
        if (session != null && session.isConnected()) {
            return;
        }

        Map<String, Object> row = jdbc.queryForMap("SELECT user, password, post FROM servers WHERE host = ?", host);
        String user = (String) row.get("user");
        String password = (String) row.get("password");
        int port = (Integer) row.get("post");

        JSch jsch = new JSch();
        session = jsch.getSession(user, host, port);
        session.setPassword(password);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");         // tắt xác minh fingerprint
        config.put("PreferredAuthentications", "password");// chỉ dùng mật khẩu
        config.put("MaxAuthTries", "3");                  //  3 lần thử
        config.put("ConnectionAttempts", "3");            // thử 3 lần là đủ
        config.put("Compression", "none");               // không nén
        session.setConfig(config);

        session.setTimeout(3000);        // socket timeout (3s)
        session.connect(3000);    // timeout khi kết nối SSH (3s)
    }

    public void connectShell() throws Exception {
        if (session == null || !session.isConnected()) {
            throw new IllegalStateException("Session chưa được kết nối.");
        }
        if (shellChannel != null && shellChannel.isConnected()) {
            return;
        }

        shellChannel = (ChannelShell) session.openChannel("shell");
        shellChannel.setPty(true);
        shellChannel.setPtyType("xterm");
        shellChannel.connect(3000);

        in = new BufferedInputStream(shellChannel.getInputStream());
        out = new BufferedOutputStream(shellChannel.getOutputStream());
        // Bỏ dữ liệu khởi tạo (MOTD, welcome message)
        Thread.sleep(100);
        while (in.available() > 0) {
            in.read(new byte[in.available()]);
        }
    }

    public String CommandExec(String command) throws JSchException, IOException {
        if (session == null || !session.isConnected()) {
            throw new JSchException("Not connected");
        }
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand(command);
        channel.connect();
        InputStream in = channel.getInputStream();
        StringBuilder out = new StringBuilder();
        byte[] buf = new byte[1024];
        while (true) {
            while (in.available() > 0) {
                int i = in.read(buf, 0, buf.length);
                if (i < 0) {
                    break;
                }
                out.append(new String(buf, 0, i));
            }
            if (channel.isClosed()) {
                break;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
        }
        return out.toString().trim();
    }

    public String CommandShellLinux(List<String> commands) throws Exception {
        if (shellChannel == null || !shellChannel.isConnected()) {
            throw new IllegalStateException("Shell channel chưa được khởi tạo hoặc đã ngắt.");
        }

        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];

        for (String cmd : commands) {
            out.write((cmd + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            // Đọc từng block với thời gian chờ
            long start = System.currentTimeMillis();
            long timeout = 2500; //thời gian display đợi lệnh thực thi và xử lí đầu ra
            while (System.currentTimeMillis() - start < timeout) {
                if (in.available() > 0) {
                    int read = in.read(buffer);
                    if (read > 0) {
                        responseStream.write(buffer, 0, read);
                        start = System.currentTimeMillis(); // reset timer nếu còn dữ liệu
                    }
                } else {
                    Thread.sleep(100);
                }
            }
        }
        return cleanOutput(responseStream.toString(StandardCharsets.UTF_8));
    }

    private String cleanOutput(String raw) {
        // Bỏ escape code và prompt
        String ansiRegex = "\u001B\\[[;\\d]*[a-zA-Z]";
        String[] lines = raw.split("\r?\n");
        StringBuilder cleaned = new StringBuilder();

        for (String line : lines) {
            String cleanLine = line.replaceAll(ansiRegex, "").trim();
            if (cleanLine.isEmpty()) {
                continue;
            }
            if (cleanLine.matches("^[\\w.@-]+[:~\\w/\\s-]*[$#>]\\s?$")) {
                continue; // bỏ dòng prompt

            }
            if (cleanLine.equalsIgnoreCase("exit")) {
                continue;
            }
            cleaned.append(cleanLine).append("\n");
        }
        return cleaned.toString().trim();
    }

    public String getOsType() {
        return this.osType;
    }

    public void setOsType(String osType) {
        this.osType = osType != null ? osType.toLowerCase() : "";
    }

    public boolean isConnected() {
        return session != null && session.isConnected();
    }

    public void disconnect() {
        if (shellChannel != null) {
            shellChannel.disconnect();
        }
        if (session != null) {
            session.disconnect();
        }
    }
}
