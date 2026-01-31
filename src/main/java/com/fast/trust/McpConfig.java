package com.fast.trust;

import com.fast.trust.tool.ScanTools;
import org.springframework.ai.support.ToolCallbacks;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class McpConfig {

    @Bean
    public List<ToolCallback> toolCallbacks(ScanTools scanTools) {
        return List.of(ToolCallbacks.from(scanTools));
    }
}
