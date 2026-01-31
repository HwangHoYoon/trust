package com.fast.trust.ai.controller;

import com.fast.trust.ai.service.AiService;
import com.fast.trust.scan.entity.ScanDetail;
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

    @GetMapping(value = "/analyze", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ScanDetail> analyzeScan(String scanId) {
        return aiService.analyzeScan(scanId);
    }
}
