package com.fast.trust.scan.controller;

import com.fast.trust.scan.service.ScanService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/scan/")
@Slf4j
public class ScanController {
    private final ScanService scanService;

    /**
     * SSE를 통한 실시간 스캔
     * GET /api/nuclei/scan/stream?url=https://example.com
     */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter scanWithStream(@RequestParam String url) {
        log.info("Starting Nuclei scan for URL: {}", url);

        SseEmitter emitter = new SseEmitter(600000L); // 5분 타임아웃

        scanService.scanUrlWithStream(url, emitter);

        return emitter;
    }

    /**
     * 일반 POST 요청으로 스캔 (결과만 반환)
     * POST /api/nuclei/scan
     */
    @PostMapping("/scan")
    public ResponseEntity<Map<String, Object>> scan(@RequestBody Map<String, String> request) {
        String url = request.get("url");
        log.info("Starting Nuclei scan for URL: {}", url);

        try {
            Map<String, Object> result = scanService.scanUrl(url);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Scan failed", e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Nuclei 버전 확인
     * GET /api/nuclei/version
     */
    @GetMapping("/version")
    public ResponseEntity<Map<String, String>> getVersion() {
        try {
            String version = scanService.getNucleiVersion();
            return ResponseEntity.ok(Map.of("version", version));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", e.getMessage()));
        }
    }
}
