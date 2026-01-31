package com.fast.trust.ai.controller;

import com.fast.trust.ai.service.AiService;
import com.fast.trust.scan.dto.SSEDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/ai/")
public class AiController {
    private final AiService aiService;

    @GetMapping(value = "/analyzeScan", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<SSEDto> analyzeScan(String scanId) {
        return aiService.analyzeScan(scanId);
    }

    @GetMapping(value = "/analyzeScanDetail", produces = MediaType.APPLICATION_JSON_VALUE)
    public SSEDto analyzeScanDetail(String scanDetailId) {
        return aiService.analyzeScanDetail(scanDetailId);
    }
}
