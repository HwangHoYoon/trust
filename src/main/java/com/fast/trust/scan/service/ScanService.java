package com.fast.trust.scan.service;

import com.fast.trust.ai.dto.AiRstDto;
import com.fast.trust.ai.service.AiService;
import com.fast.trust.scan.dto.SSEDto;
import com.fast.trust.scan.dto.SSE_TYPE;
import com.fast.trust.scan.dto.ScanScoreResult;
import com.fast.trust.scan.entity.ScanDetail;
import com.fast.trust.scan.entity.ScanMaster;
import com.fast.trust.scan.repository.ScanDetailRepository;
import com.fast.trust.scan.repository.ScanMasterRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanService {

    @Value("${nuclei.path}")
    private String nucleiPath;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ScanMasterRepository scanMasterRepository;
    private final ScanDetailRepository scanDetailRepository;
    private final AiService aiService;

    private static final Set<String> HIGH_RISK_INFO_TEMPLATES = Set.of(
            "ssl-expired",
            "tls-deprecated",
            "missing-security-headers",
            "eol-software"
    );

    /**
     * SSE를 통한 실시간 스캔
     */
    public void scanUrlWithStream(String url, SseEmitter emitter) {
        String normalizedUrl = normalizeUrl(url);

        CompletableFuture.runAsync(() -> {
            Process process = null; // ✅ try-finally에서 정리하기 위해
            BufferedReader reader = null;
            String scanId = UUID.randomUUID().toString();

            ScanMaster scanMaster = new ScanMaster(scanId, normalizedUrl);
            scanMasterRepository.save(scanMaster);

            try {
                SSEDto sseDto = new SSEDto();
                sseDto.setType(SSE_TYPE.START.name());
                sseDto.setScanId(scanId);
                emitter.send(SseEmitter.event()
                        .name("init")
                        .data(sseDto));

                ProcessBuilder processBuilder = new ProcessBuilder(
                        nucleiPath,
                        "-u", normalizedUrl,
                        "-jsonl",
                        "-stats",
                        "-silent"
                );

                processBuilder.redirectErrorStream(true);
                process = processBuilder.start();

                reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
                );

                String line;
                int lineNumber = 0;
                List<Map<String, Object>> findings = new ArrayList<>();

                while ((line = reader.readLine()) != null) {
                    lineNumber++;

                    String cleanLine = line.replaceAll("\u001b\\[[0-9;]*m", "");
                    try {
                        // JSON 라인 파싱
                        if (cleanLine.trim().startsWith("{")) {
                            Map<String, Object> jsonData = objectMapper.readValue(cleanLine, Map.class);

                            jsonData = filterLongFields(jsonData);

                            // 진행 상황 데이터 생성
                            Map<String, Object> progressData = new HashMap<>();
                            progressData.put("lineNumber", lineNumber);
                            progressData.put("timestamp", System.currentTimeMillis());
                            progressData.put("data", jsonData);
                            sseDto = new SSEDto();
                            // 취약점 발견 시
                            if (jsonData.containsKey("info")) {
                                findings.add(jsonData);
                                try {
                                    sseDto.setType(SSE_TYPE.FIND.name());
                                    ScanDetail detail = toScanDetail(scanId, jsonData);
                                    scanDetailRepository.save(detail);
                                    sseDto.setScanDetailId(String.valueOf(detail.getId()));
                                    sseDto.setName(detail.getName());
                                    sseDto.setSeverity(detail.getSeverity());
                                    sseDto.setDescription(detail.getDescription());
                                    sseDto.setAiAnalyzed(false);
                                    log.info("Finding detected: {} - {}",
                                            detail.getName(),
                                            detail.getSeverity());
                                } catch (Exception e) {
                                    log.error("Failed to save ScanDetail: {}", e.getMessage(), e);
                                }
                                progressData.put("type", "finding");
                                progressData.put("totalFindings", findings.size());
                            } else if (jsonData.containsKey("stats")) {
                                // 통계 정보
                                progressData.put("type", "stats");
                                sseDto.setType(SSE_TYPE.PROGRESS.name());
                                sseDto.setPercent((String)jsonData.get("percent"));
                            } else {
                                progressData.put("type", "info");
                                sseDto.setType(SSE_TYPE.PROGRESS.name());
                                sseDto.setPercent((String)jsonData.get("percent"));
                            }

                            // SSE로 전송
                            emitter.send(SseEmitter.event()
                                    .name("progress")
                                    .data(sseDto));

                            log.debug("Line {}: {}", lineNumber, cleanLine); // ✅ debug 레벨로 변경

                        } else if (!cleanLine.trim().isEmpty()) { // ✅ 빈 줄 무시
                            // 일반 텍스트 출력
                            Map<String, Object> textData = new HashMap<>();
                            textData.put("lineNumber", lineNumber);
                            textData.put("type", "text");
                            textData.put("message", cleanLine);
                            textData.put("timestamp", System.currentTimeMillis());

/*                            emitter.send(SseEmitter.event()
                                    .name("progress")
                                    .data(textData));*/

                            log.debug("Text line {}: {}", lineNumber, cleanLine);
                        }
                    } catch (JsonProcessingException e) {
                        log.warn("Failed to parse JSON at line {}: {}", lineNumber, cleanLine);

                        Map<String, Object> errorData = new HashMap<>();
                        errorData.put("lineNumber", lineNumber);
                        errorData.put("type", "parse_error");
                        errorData.put("message", "JSON parse failed: " + e.getMessage());
                        errorData.put("rawLine", cleanLine);

                        emitter.send(SseEmitter.event()
                                .name("warning")
                                .data(errorData));

                    } catch (Exception e) {
                        log.error("Error processing line {}: {}", lineNumber, cleanLine, e);

                        // 에러 정보 전송
                        Map<String, Object> errorData = new HashMap<>();
                        errorData.put("lineNumber", lineNumber);
                        errorData.put("type", "error");
                        errorData.put("message", e.getMessage());
                        errorData.put("rawLine", cleanLine);

                        emitter.send(SseEmitter.event()
                                .name("error")
                                .data(errorData));
                    }
                }

                // ✅ 타임아웃 포함 대기
                boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5분

                if (!finished) {
                    log.warn("Nuclei process timeout, forcibly destroying");
                    process.destroyForcibly();
                }

                int exitCode = process.exitValue();
                scanMaster.complete();

                List<ScanDetail> details = scanDetailRepository.findByScanId(scanId);
                ScanScoreResult score = calculateScore(details);
                scanMaster.setScore(score.score());
                scanMaster.setGrade(score.grade());
                scanMasterRepository.save(scanMaster);

                // 완료 메시지 전송
                Map<String, Object> completionData = new HashMap<>();
                completionData.put("type", "complete");
                completionData.put("exitCode", exitCode);
                completionData.put("totalLines", lineNumber);
                completionData.put("totalFindings", findings.size());
                completionData.put("findings", findings);
                completionData.put("timestamp", System.currentTimeMillis());
                completionData.put("url", normalizedUrl); // ✅ URL 추가

                sseDto = new SSEDto();
                sseDto.setType(SSE_TYPE.END.name());
                sseDto.setGrade(score.grade());
                sseDto.setScore(score.score());

                emitter.send(SseEmitter.event()
                        .name("complete")
                        .data(sseDto));

                emitter.complete();

                log.info("Scan completed for {}: Exit code: {}, Total lines: {}, Findings: {}",
                        normalizedUrl, exitCode, lineNumber, findings.size());

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // ✅ 인터럽트 상태 복원
                log.error("Scan interrupted for {}", normalizedUrl, e);

                try {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data(Map.of(
                                    "type", "interrupted",
                                    "message", "Scan was interrupted"
                            )));
                } catch (IOException ignored) {}
                emitter.completeWithError(e);

            } catch (Exception e) {
                log.error("Error during scan for {}", normalizedUrl, e);
                scanMaster.fail(e.getMessage());
                scanMasterRepository.save(scanMaster);

                try {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data(Map.of(
                                    "type", "fatal",
                                    "message", e.getMessage(),
                                    "url", normalizedUrl
                            )));
                } catch (IOException ignored) {}
                emitter.completeWithError(e);

            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e) {
                        log.warn("Failed to close reader", e);
                    }
                }

                if (process != null && process.isAlive()) {
                    log.warn("Process still alive, destroying forcibly");
                    process.destroyForcibly();
                }
            }
        });
    }

    /**
     * Nuclei 버전 확인
     */
    public String getNucleiVersion() throws Exception {
        ProcessBuilder processBuilder = new ProcessBuilder(nucleiPath, "-version");
        processBuilder.redirectErrorStream(true);

        Process process = processBuilder.start();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
        );

        StringBuilder output = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }

        process.waitFor();

        String fullOutput = output.toString();

        // ANSI 색상 코드 제거
        String cleanOutput = fullOutput.replaceAll("\u001b\\[[0-9;]*m", "");

        // "v3.7.0" 형태의 버전만 추출
        Pattern pattern = Pattern.compile("v[0-9]+\\.[0-9]+\\.[0-9]+");
        Matcher matcher = pattern.matcher(cleanOutput);

        if (matcher.find()) {
            return matcher.group(0); // "v3.7.0" 반환
        }

        return "Unknown";
    }

    /**
     * URL 형식 검증 및 보정
     */
    private String normalizeUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be empty");
        }

        url = url.trim();

        // http:// 또는 https://가 없으면 추가
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }

        return url;
    }

    private Map<String, Object> filterLongFields(Map<String, Object> data) {
        Map<String, Object> filtered = new HashMap<>(data);

/*        List<String> fieldsToRemove = Arrays.asList(
                "response",      // HTML 전체
                "request",       // 요청 전체
                "curl-command"   // curl 명령어
        );*/

        List<String> fieldsToRemove = Arrays.asList(
                "response",      // HTML 전체
                "request"       // 요청 전체
        );

        for (String field : fieldsToRemove) {
            if (filtered.containsKey(field)) {
                String value = String.valueOf(filtered.get(field));
                log.debug("Removed field '{}' with length: {}", field, value.length());
                filtered.remove(field);
            }
        }

        // extracted-results는 10개로 제한
        if (filtered.containsKey("extracted-results")) {
            Object extractedResults = filtered.get("extracted-results");
            if (extractedResults instanceof List) {
                List<?> list = (List<?>) extractedResults;
                if (list.size() > 10) {
                    filtered.put("extracted-results", list.subList(0, 10));
                    filtered.put("extracted-results-count", list.size());
                    log.debug("Truncated extracted-results from {} to 10", list.size());
                }
            }
        }

        return filtered;
    }

    private ScanDetail toScanDetail(String scanId, Map<String, Object> jsonData) {
        Map<String, Object> info = (Map<String, Object>) jsonData.get("info");

        return ScanDetail.builder()
                .scanId(scanId)
                .templateId((String) jsonData.get("template-id"))
                .name(info != null ? (String) info.get("name") : null)
                .severity(info != null ? (String) info.get("severity") : null)
                .matchedAt((String) jsonData.get("matched-at"))
                .description(info != null ? (String) info.get("description") : null)
                .tags((List<String>) info.get("tags"))
                .extractedResults((List<String>) jsonData.get("extracted-results"))
                .fullResult(jsonData)
                .highRiskInfo(
                        info != null &&
                                List.of("critical", "high")
                                        .contains(String.valueOf(info.get("severity")).toLowerCase())
                )
                .aiAnalyzed(false)
                .build();
    }

    public ScanScoreResult calculateScore(List<ScanDetail> scanDetailList) {

        int score = 100;

        Map<String, Integer> severityCounts = new HashMap<>();
        severityCounts.put("critical", 0);
        severityCounts.put("high", 0);
        severityCounts.put("medium", 0);
        severityCounts.put("low", 0);
        severityCounts.put("info", 0);

        for (ScanDetail v : scanDetailList) {
            String severity = Optional.ofNullable(v.getSeverity())
                    .orElse("info")
                    .toLowerCase();

            severityCounts.computeIfPresent(severity, (k, val) -> val + 1);

            // High-risk INFO
            if ("info".equals(severity)) {
                String templateId = Optional.ofNullable(v.getTemplateId())
                        .orElse("")
                        .toLowerCase();

                if (HIGH_RISK_INFO_TEMPLATES.stream().anyMatch(templateId::contains)) {
                    score -= 1;
                }
            }
        }

        score -= Math.min(severityCounts.get("critical") * 25, 50);
        score -= Math.min(severityCounts.get("high") * 15, 30);
        score -= Math.min(severityCounts.get("medium") * 5, 15);
        score -= Math.min(severityCounts.get("low") * 2, 6);

        score = Math.max(score, 0);

        return new ScanScoreResult(score, grade(score));
    }

    private String grade(int score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B+";
        if (score >= 70) return "B";
        if (score >= 60) return "B-";
        if (score >= 50) return "C";
        if (score >= 40) return "D";
        return "F";
    }

    public void scanUrlWithStreamAi(String url, SseEmitter emitter) {
        String normalizedUrl = normalizeUrl(url);

        CompletableFuture.runAsync(() -> {
            Process process = null; // ✅ try-finally에서 정리하기 위해
            BufferedReader reader = null;
            String scanId = UUID.randomUUID().toString();

            ScanMaster scanMaster = new ScanMaster(scanId, normalizedUrl);
            scanMasterRepository.save(scanMaster);

            try {
                SSEDto sseDto = new SSEDto();
                sseDto.setType(SSE_TYPE.START.name());
                sseDto.setScanId(scanId);
                emitter.send(SseEmitter.event()
                        .name("init")
                        .data(sseDto));

                ProcessBuilder processBuilder = new ProcessBuilder(
                        nucleiPath,
                        "-u", normalizedUrl,
                        "-jsonl",
                        "-stats",
                        "-silent"
                );

                processBuilder.redirectErrorStream(true);
                process = processBuilder.start();

                reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
                );

                String line;
                int lineNumber = 0;
                List<Map<String, Object>> findings = new ArrayList<>();

                while ((line = reader.readLine()) != null) {
                    lineNumber++;

                    String cleanLine = line.replaceAll("\u001b\\[[0-9;]*m", "");
                    try {
                        // JSON 라인 파싱
                        if (cleanLine.trim().startsWith("{")) {
                            Map<String, Object> jsonData = objectMapper.readValue(cleanLine, Map.class);

                            jsonData = filterLongFields(jsonData);

                            // 진행 상황 데이터 생성
                            Map<String, Object> progressData = new HashMap<>();
                            progressData.put("lineNumber", lineNumber);
                            progressData.put("timestamp", System.currentTimeMillis());
                            progressData.put("data", jsonData);
                            sseDto = new SSEDto();
                            // 취약점 발견 시
                            if (jsonData.containsKey("info")) {
                                findings.add(jsonData);
                                try {
                                    ScanDetail detail = toScanDetail(scanId, jsonData);
                                    scanDetailRepository.save(detail);
                                    AiRstDto result = aiService.analyze(detail);
                                    sseDto = aiService.saveResult(detail, result);
                                    sseDto.setType(SSE_TYPE.FIND.name());
                                    log.info("Finding detected: {} - {}",
                                            detail.getName(),
                                            detail.getSeverity());
                                } catch (Exception e) {
                                    log.error("Failed to save ScanDetail: {}", e.getMessage(), e);
                                }
                                progressData.put("type", "finding");
                                progressData.put("totalFindings", findings.size());
                            } else if (jsonData.containsKey("stats")) {
                                // 통계 정보
                                progressData.put("type", "stats");
                                sseDto.setType(SSE_TYPE.PROGRESS.name());
                                sseDto.setPercent((String)jsonData.get("percent"));
                            } else {
                                progressData.put("type", "info");
                                sseDto.setType(SSE_TYPE.PROGRESS.name());
                                sseDto.setPercent((String)jsonData.get("percent"));
                            }

                            // SSE로 전송
                            emitter.send(SseEmitter.event()
                                    .name("progress")
                                    .data(sseDto));

                            log.debug("Line {}: {}", lineNumber, cleanLine); // ✅ debug 레벨로 변경

                        } else if (!cleanLine.trim().isEmpty()) { // ✅ 빈 줄 무시
                            // 일반 텍스트 출력
                            Map<String, Object> textData = new HashMap<>();
                            textData.put("lineNumber", lineNumber);
                            textData.put("type", "text");
                            textData.put("message", cleanLine);
                            textData.put("timestamp", System.currentTimeMillis());

/*                            emitter.send(SseEmitter.event()
                                    .name("progress")
                                    .data(textData));*/

                            log.debug("Text line {}: {}", lineNumber, cleanLine);
                        }
                    } catch (JsonProcessingException e) {
                        log.warn("Failed to parse JSON at line {}: {}", lineNumber, cleanLine);

                        Map<String, Object> errorData = new HashMap<>();
                        errorData.put("lineNumber", lineNumber);
                        errorData.put("type", "parse_error");
                        errorData.put("message", "JSON parse failed: " + e.getMessage());
                        errorData.put("rawLine", cleanLine);

                        emitter.send(SseEmitter.event()
                                .name("warning")
                                .data(errorData));

                    } catch (Exception e) {
                        log.error("Error processing line {}: {}", lineNumber, cleanLine, e);

                        // 에러 정보 전송
                        Map<String, Object> errorData = new HashMap<>();
                        errorData.put("lineNumber", lineNumber);
                        errorData.put("type", "error");
                        errorData.put("message", e.getMessage());
                        errorData.put("rawLine", cleanLine);

                        emitter.send(SseEmitter.event()
                                .name("error")
                                .data(errorData));
                    }
                }

                // ✅ 타임아웃 포함 대기
                boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5분

                if (!finished) {
                    log.warn("Nuclei process timeout, forcibly destroying");
                    process.destroyForcibly();
                }

                int exitCode = process.exitValue();
                scanMaster.complete();

                List<ScanDetail> details = scanDetailRepository.findByScanId(scanId);
                ScanScoreResult score = calculateScore(details);
                scanMaster.setScore(score.score());
                scanMaster.setGrade(score.grade());
                scanMasterRepository.save(scanMaster);

                // 완료 메시지 전송
                Map<String, Object> completionData = new HashMap<>();
                completionData.put("type", "complete");
                completionData.put("exitCode", exitCode);
                completionData.put("totalLines", lineNumber);
                completionData.put("totalFindings", findings.size());
                completionData.put("findings", findings);
                completionData.put("timestamp", System.currentTimeMillis());
                completionData.put("url", normalizedUrl); // ✅ URL 추가

                sseDto = new SSEDto();
                sseDto.setType(SSE_TYPE.END.name());
                sseDto.setGrade(score.grade());
                sseDto.setScore(score.score());

                emitter.send(SseEmitter.event()
                        .name("complete")
                        .data(sseDto));

                emitter.complete();

                log.info("Scan completed for {}: Exit code: {}, Total lines: {}, Findings: {}",
                        normalizedUrl, exitCode, lineNumber, findings.size());

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // ✅ 인터럽트 상태 복원
                log.error("Scan interrupted for {}", normalizedUrl, e);

                try {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data(Map.of(
                                    "type", "interrupted",
                                    "message", "Scan was interrupted"
                            )));
                } catch (IOException ignored) {}
                emitter.completeWithError(e);

            } catch (Exception e) {
                log.error("Error during scan for {}", normalizedUrl, e);
                scanMaster.fail(e.getMessage());
                scanMasterRepository.save(scanMaster);

                try {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data(Map.of(
                                    "type", "fatal",
                                    "message", e.getMessage(),
                                    "url", normalizedUrl
                            )));
                } catch (IOException ignored) {}
                emitter.completeWithError(e);

            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e) {
                        log.warn("Failed to close reader", e);
                    }
                }

                if (process != null && process.isAlive()) {
                    log.warn("Process still alive, destroying forcibly");
                    process.destroyForcibly();
                }
            }
        });
    }

    public List<SSEDto> mcpAll(String url) {
        String normalizedUrl = normalizeUrl(url);

        List<SSEDto> dtoList = new ArrayList<>();
        CompletableFuture.runAsync(() -> {
            Process process = null; // ✅ try-finally에서 정리하기 위해
            BufferedReader reader = null;
            String scanId = UUID.randomUUID().toString();

            ScanMaster scanMaster = new ScanMaster(scanId, normalizedUrl);
            scanMasterRepository.save(scanMaster);

            try {
                SSEDto sseDto = new SSEDto();
                sseDto.setType(SSE_TYPE.START.name());
                sseDto.setScanId(scanId);
                dtoList.add(sseDto);

                ProcessBuilder processBuilder = new ProcessBuilder(
                        nucleiPath,
                        "-u", normalizedUrl,
                        "-jsonl",
                        "-stats",
                        "-silent"
                );

                processBuilder.redirectErrorStream(true);
                process = processBuilder.start();

                reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
                );

                String line;
                int lineNumber = 0;
                List<Map<String, Object>> findings = new ArrayList<>();

                while ((line = reader.readLine()) != null) {
                    lineNumber++;

                    String cleanLine = line.replaceAll("\u001b\\[[0-9;]*m", "");
                    try {
                        // JSON 라인 파싱
                        if (cleanLine.trim().startsWith("{")) {
                            Map<String, Object> jsonData = objectMapper.readValue(cleanLine, Map.class);

                            jsonData = filterLongFields(jsonData);

                            // 진행 상황 데이터 생성
                            Map<String, Object> progressData = new HashMap<>();
                            progressData.put("lineNumber", lineNumber);
                            progressData.put("timestamp", System.currentTimeMillis());
                            progressData.put("data", jsonData);
                            sseDto = new SSEDto();
                            // 취약점 발견 시
                            if (jsonData.containsKey("info")) {
                                findings.add(jsonData);
                                try {
                                    ScanDetail detail = toScanDetail(scanId, jsonData);
                                    scanDetailRepository.save(detail);
                                    AiRstDto result = aiService.analyze(detail);
                                    sseDto = aiService.saveResult(detail, result);
                                    sseDto.setType(SSE_TYPE.FIND.name());
                                    log.info("Finding detected: {} - {}",
                                            detail.getName(),
                                            detail.getSeverity());
                                } catch (Exception e) {
                                    log.error("Failed to save ScanDetail: {}", e.getMessage(), e);
                                }
                                progressData.put("type", "finding");
                                progressData.put("totalFindings", findings.size());
                            } else if (jsonData.containsKey("stats")) {
                                // 통계 정보
                                progressData.put("type", "stats");
                                sseDto.setType(SSE_TYPE.PROGRESS.name());
                                sseDto.setPercent((String)jsonData.get("percent"));
                            } else {
                                progressData.put("type", "info");
                                sseDto.setType(SSE_TYPE.PROGRESS.name());
                                sseDto.setPercent((String)jsonData.get("percent"));
                            }
                            dtoList.add(sseDto);

                            log.debug("Line {}: {}", lineNumber, cleanLine); // ✅ debug 레벨로 변경

                        } else if (!cleanLine.trim().isEmpty()) { // ✅ 빈 줄 무시
                            // 일반 텍스트 출력
                            Map<String, Object> textData = new HashMap<>();
                            textData.put("lineNumber", lineNumber);
                            textData.put("type", "text");
                            textData.put("message", cleanLine);
                            textData.put("timestamp", System.currentTimeMillis());

/*                            emitter.send(SseEmitter.event()
                                    .name("progress")
                                    .data(textData));*/

                            log.debug("Text line {}: {}", lineNumber, cleanLine);
                        }
                    } catch (JsonProcessingException e) {
                        log.warn("Failed to parse JSON at line {}: {}", lineNumber, cleanLine);

                        Map<String, Object> errorData = new HashMap<>();
                        errorData.put("lineNumber", lineNumber);
                        errorData.put("type", "parse_error");
                        errorData.put("message", "JSON parse failed: " + e.getMessage());
                        errorData.put("rawLine", cleanLine);
                        dtoList.add(sseDto);

                    } catch (Exception e) {
                        log.error("Error processing line {}: {}", lineNumber, cleanLine, e);

                        // 에러 정보 전송
                        Map<String, Object> errorData = new HashMap<>();
                        errorData.put("lineNumber", lineNumber);
                        errorData.put("type", "error");
                        errorData.put("message", e.getMessage());
                        errorData.put("rawLine", cleanLine);
                        dtoList.add(sseDto);
                    }
                }

                // ✅ 타임아웃 포함 대기
                boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5분

                if (!finished) {
                    log.warn("Nuclei process timeout, forcibly destroying");
                    process.destroyForcibly();
                }

                int exitCode = process.exitValue();
                scanMaster.complete();

                List<ScanDetail> details = scanDetailRepository.findByScanId(scanId);
                ScanScoreResult score = calculateScore(details);
                scanMaster.setScore(score.score());
                scanMaster.setGrade(score.grade());
                scanMasterRepository.save(scanMaster);

                // 완료 메시지 전송
                Map<String, Object> completionData = new HashMap<>();
                completionData.put("type", "complete");
                completionData.put("exitCode", exitCode);
                completionData.put("totalLines", lineNumber);
                completionData.put("totalFindings", findings.size());
                completionData.put("findings", findings);
                completionData.put("timestamp", System.currentTimeMillis());
                completionData.put("url", normalizedUrl); // ✅ URL 추가

                sseDto = new SSEDto();
                sseDto.setType(SSE_TYPE.END.name());
                sseDto.setGrade(score.grade());
                sseDto.setScore(score.score());
                dtoList.add(sseDto);

                log.info("Scan completed for {}: Exit code: {}, Total lines: {}, Findings: {}",
                        normalizedUrl, exitCode, lineNumber, findings.size());

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // ✅ 인터럽트 상태 복원
                log.error("Scan interrupted for {}", normalizedUrl, e);
            } catch (Exception e) {
                log.error("Error during scan for {}", normalizedUrl, e);
                scanMaster.fail(e.getMessage());
                scanMasterRepository.save(scanMaster);
            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e) {
                        log.warn("Failed to close reader", e);
                    }
                }

                if (process != null && process.isAlive()) {
                    log.warn("Process still alive, destroying forcibly");
                    process.destroyForcibly();
                }
            }
        });
        return null;
    }
}
