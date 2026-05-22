package com.example.ct491.ssh;

import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import reactor.core.publisher.Sinks;

@RestController
public class SseNotifier {

    // Tạo sink tĩnh, đa luồng, buffer để đẩy message
    private static final Sinks.Many<String> sink = Sinks.many().multicast().onBackpressureBuffer();
    private static SseEmitter emitter;

    public static SseEmitter subscribe() {
        emitter = new SseEmitter(0L); 
        return emitter;
    }

    public static void notify(String message) {
        try {
            if (emitter != null) {
                emitter.send(message);
            }
        } catch (IOException e) {
            emitter = null;
        }
    }

    // API SSE để client đăng ký nhận tin
   @GetMapping("/ssh-logs")
    public SseEmitter streamSshLogs() {
        return SseNotifier.subscribe();
    }
}