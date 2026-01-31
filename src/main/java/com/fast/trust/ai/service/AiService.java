package com.fast.trust.ai.service;

import com.fast.trust.ai.dto.AiRstDto;
import com.fast.trust.scan.dto.SSEDto;
import com.fast.trust.scan.dto.SSE_TYPE;
import com.fast.trust.scan.entity.ScanDetail;
import com.fast.trust.scan.repository.ScanDetailRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Slf4j
public class AiService {
    private final ChatClient chatClient;
    private final ObjectMapper objectMapper;
    private final ScanDetailRepository scanDetailRepository;

    public AiService(
            ChatClient.Builder builder,
            ScanDetailRepository scanDetailRepository,
            ObjectMapper objectMapper
    ) {
        this.chatClient = builder.build();
        this.scanDetailRepository = scanDetailRepository;
        this.objectMapper = objectMapper;
    }

    private static final String SYSTEM_PROMPT = """
당신은 보안 전문가입니다. Nuclei 스캔 결과를 분석하여:
1. 각 취약점의 심각도와 영향 범위를 초보자도 이해할 수 있게 설명
2. 구체적인 수정 코드 제시 (Before/After)
3. 단계별 수정 가이드 제공

반드시 아래 JSON 형식으로만 응답하세요:
{
  "description": "취약점 설명",
  "impact": "영향 범위",
  "category": "api_leak | exposure | misconfig | cve | privacy_risk",
  "before_code": "취약한 코드 예시",
  "after_code": "수정된 코드",
  "fix_steps": ["1단계", "2단계"],
  "fix_complexity": "simple | moderate | complex",
  "references": ["URL"]
}

- JSON은 반드시 완결된 형태로 출력

중요: JSON 외 다른 텍스트는 절대 포함하지 마세요.
""";

    public AiRstDto analyze(ScanDetail aiReqDto) {
        String userPrompt = buildPrompt(aiReqDto);

        try {
            String response = chatClient.prompt()
                    .system(SYSTEM_PROMPT)
                    .user(userPrompt)
                    .call()
                    .content();

            return parseResponse(aiReqDto, response);

        } catch (Exception e) {
            return defaultAnalysis(aiReqDto, e.getMessage());
        }
    }

    /* ===================== 내부 메서드 ===================== */

    private String buildPrompt(ScanDetail aiReqDto) {
        StringBuilder sb = new StringBuilder();
        sb.append("다음 보안 취약점을 분석해주세요:\n\n");
        sb.append("템플릿 ID: ").append(aiReqDto.getTemplateId()).append("\n");
        sb.append("취약점 이름: ").append(aiReqDto.getName()).append("\n");
        sb.append("심각도: ").append(aiReqDto.getSeverity()).append("\n");
        sb.append("탐지 위치: ").append(aiReqDto.getMatchedAt()).append("\n");

        if (aiReqDto.getExtractedResults() != null && !aiReqDto.getExtractedResults().isEmpty()) {
            sb.append("추출 데이터: ")
                    .append(String.join(", ", aiReqDto.getExtractedResults()))
                    .append("\n");
        }

        return sb.toString();
    }

    private AiRstDto parseResponse(ScanDetail scanDetail, String text) {
        try {
            if (text == null || text.isBlank()) {
                throw new IllegalArgumentException("Empty AI response");
            }

            String cleaned = text.trim();

            // 1️⃣ ``` 제거
            cleaned = cleaned.replaceAll("```json", "")
                    .replaceAll("```", "")
                    .trim();

            // 2️⃣ JSON 블록 추출
            String jsonOnly = extractJsonBlock(cleaned);

            // 3️⃣ 🔥 잘못된 이중 따옴표 복구
            jsonOnly = normalizeBrokenJson(jsonOnly);

            // 4️⃣ JSON 파싱
            JsonNode json = objectMapper.readTree(jsonOnly);

            return new AiRstDto(
                    scanDetail.getId(),
                    json.path("description").asText(),
                    json.path("impact").asText(),
                    json.path("category").asText("exposure"),
                    json.path("before_code").asText(),
                    json.path("after_code").asText(),
                    objectMapper.convertValue(
                            json.path("fix_steps"),
                            new TypeReference<List<String>>() {}
                    ),
                    json.path("fix_complexity").asText("moderate"),
                    objectMapper.convertValue(
                            json.path("references"),
                            new TypeReference<List<String>>() {}
                    ),
                    "claude-sonnet-4",
                    1.0,
                    java.time.LocalDateTime.now(),
                    text
            );

        } catch (Exception e) {
            log.error("AI 응답 파싱 실패", e);

            return new AiRstDto(
                    scanDetail.getId(),
                    "AI 응답 파싱 실패",
                    "응답 JSON이 손상되었거나 미완성 상태입니다.",
                    "exposure",
                    "",
                    "",
                    List.of(),
                    "moderate",
                    List.of(),
                    "claude-sonnet-4",
                    0.0,
                    java.time.LocalDateTime.now(),
                    text
            );
        }
    }

    private AiRstDto defaultAnalysis(ScanDetail scanDetail, String error) {
        return new AiRstDto(
                scanDetail.getId(),
                "이 취약점은 " + scanDetail.getName() + " 보안 문제입니다.",
                "공격자가 이를 악용할 수 있습니다.",
                "exposure",
                "// 취약 코드 확인 필요",
                "// 수정 코드 적용",
                List.of(
                        "취약점 위치 확인",
                        "권장 수정 적용",
                        "재스캔 수행"
                ),
                "moderate",
                List.of(),
                "claude-sonnet-4",
                0.0,
                java.time.LocalDateTime.now(),
                error
        );
    }

    public List<SSEDto> analyzeScan(String scanId) {
        List<ScanDetail> scanDetailList = scanDetailRepository.findByScanId(scanId);
        List<SSEDto> sseDtoList = new ArrayList<>();
        for (ScanDetail scanDetail : scanDetailList) {
            AiRstDto result = analyze(scanDetail);
            sseDtoList.add(saveResult(scanDetail, result));
        }

        return sseDtoList;
    }

    public SSEDto saveResult(ScanDetail scanDetail, AiRstDto result) {

        // 1️⃣ 전체 AI 결과 JSON (백업 / 디버깅용)
        Map<String, Object> aiResult = new HashMap<>();
        aiResult.put("description", result.description());
        aiResult.put("impact", result.impact());
        aiResult.put("category", result.category());
        aiResult.put("beforeCode", result.beforeCode());
        aiResult.put("afterCode", result.afterCode());
        aiResult.put("fixSteps", result.fixSteps());
        aiResult.put("fixComplexity", result.fixComplexity());
        aiResult.put("references", result.references());
        aiResult.put("aiModel", result.aiModel());
        aiResult.put("confidence", result.confidence());
        aiResult.put("analyzedAt", result.analyzedAt());
        aiResult.put("rawResponse", result.rawResponse());

        scanDetail.setAiResult(aiResult);

        // 2️⃣ 컬럼 정규화 저장 (검색 / 필터 / UI용)
        scanDetail.setAiDescription(result.description());
        scanDetail.setAiImpact(result.impact());
        scanDetail.setAiCategory(result.category());
        scanDetail.setAiBeforeCode(result.beforeCode());
        scanDetail.setAiAfterCode(result.afterCode());
        scanDetail.setAiFixSteps(result.fixSteps());
        scanDetail.setAiFixComplexity(result.fixComplexity());
        scanDetail.setAiReferences(result.references());
        scanDetail.setAiModel(result.aiModel());
        scanDetail.setAiConfidence(result.confidence());
        scanDetail.setAiAnalyzedAt(result.analyzedAt());
        scanDetail.setAiRawResponse(result.rawResponse());

        // 3️⃣ 상태 플래그
        scanDetail.setAiAnalyzed(true);

        scanDetailRepository.save(scanDetail);
        SSEDto sSEDto = new SSEDto();
        sSEDto.setType(SSE_TYPE.AI.name());
        sSEDto.setScanId(scanDetail.getScanId());
        sSEDto.setScanDetailId(String.valueOf(scanDetail.getId()));
        sSEDto.setName(scanDetail.getName());
        sSEDto.setDescription(scanDetail.getDescription());
        sSEDto.setSeverity(scanDetail.getSeverity());
        sSEDto.setAiAnalyzed(true);
        sSEDto.setAiImpact(scanDetail.getAiImpact());
        sSEDto.setAiReferences(scanDetail.getAiReferences());
        sSEDto.setAiFixSteps(scanDetail.getAiFixSteps());
        sSEDto.setAiBeforeCode(scanDetail.getAiBeforeCode());
        sSEDto.setAiAfterCode(scanDetail.getAiAfterCode());
        sSEDto.setAiDescription(scanDetail.getAiDescription());
        return sSEDto;
    }

    private String extractJsonBlock(String text) {
        int start = text.indexOf("{");
        int end = text.lastIndexOf("}");

        if (start == -1 || end == -1 || end <= start) {
            throw new IllegalArgumentException("JSON block not found or incomplete");
        }

        return text.substring(start, end + 1);
    }

    private String normalizeBrokenJson(String json) {
        // ""key"" → "key"
        json = json.replaceAll("\"\"([^\"]+)\"\"", "\"$1\"");

        // ""value"" → "value"
        json = json.replaceAll(":\\s*\"\"([^\"]*)\"\"", ": \"$1\"");

        return json;
    }

    public SSEDto analyzeScanDetail(String scanDetailId) {
        ScanDetail scanDetail = scanDetailRepository.findById(Long.parseLong(scanDetailId)).orElseThrow(() -> new IllegalArgumentException("존재하지 않는 scanDetailId: " + scanDetailId));;
        AiRstDto result = analyze(scanDetail);
        return saveResult(scanDetail, result);
    }
}
