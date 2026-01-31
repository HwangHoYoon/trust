package com.fast.trust.scan.controller;

import com.fast.trust.scan.dto.SSEDto;
import com.fast.trust.scan.service.ScanService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
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

    @GetMapping(value = "/streamAll", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamAll(@RequestParam String url) throws Exception {
        SseEmitter emitter = new SseEmitter(600000L); // 5분 타임아웃
        scanService.scanUrlWithStreamAi(url, emitter);
        return emitter;
    }

    @GetMapping(value = "/mcpAll")
    public List<SSEDto> mcpAll(@RequestParam String url) throws Exception {
        return scanService.mcpAll(url);
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
