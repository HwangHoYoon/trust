package com.fast.trust.tool;

import com.fast.trust.scan.service.ScanService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class ScanTools {

    private final ScanService scanService;

    @Tool(name = "scan_url", description = "scan_url desc")
    public String scanUrl(String url) {
        Map<String, Object> result = scanService.mcpAll(url);
        try {
            return new ObjectMapper().writeValueAsString(result);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
