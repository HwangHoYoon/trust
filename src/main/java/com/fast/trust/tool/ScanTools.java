package com.fast.trust.tool;

import com.fast.trust.scan.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class ScanTools {

    private final ScanService scanService;

    @Tool(name = "scan_url", description = "scan_url desc")
    public Map<String, Object> scanUrl(String url) {
        return scanService.mcpAll(url);
    }
}
