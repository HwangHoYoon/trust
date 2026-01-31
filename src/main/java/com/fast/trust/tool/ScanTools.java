package com.fast.trust.tool;

import com.fast.trust.scan.service.ScanService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class ScanTools {
    private final ScanService scanService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ScanTools(ScanService scanService) {
        this.scanService = scanService;
    }

    @Tool(name = "scan_url")
    public String scanUrl(String url) {
        Map<String,Object> result = scanService.mcpAll(url);
        try {
            return objectMapper.writeValueAsString(result);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
