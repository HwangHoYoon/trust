package com.fast.trust.scan.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Table(name = "scan_master") // 테이블 이름 명시
@NoArgsConstructor
public class ScanMaster {
    @Id
    private String id;

    @Column(name = "target_url") // 명시적으로 snake_case 지정
    private String targetUrl;

    @Column(name = "status")
    private String status;

    @Column(name = "created_at") // 명시적으로 snake_case 지정
    private LocalDateTime createdAt;

    @Column(name = "completed_at") // 명시적으로 snake_case 지정
    private LocalDateTime completedAt;

    @Column(name = "error_message", columnDefinition = "TEXT") // 명시적으로 snake_case 지정
    private String errorMessage;

    @Column(name = "score")
    @Setter
    private Integer score;

    @Column(name = "grade")
    @Setter
    private String grade;

    public ScanMaster(String id, String targetUrl) {
        this.id = id;
        this.targetUrl = targetUrl;
        this.status = "PROCESSING";
        this.createdAt = LocalDateTime.now();
    }

    public void complete() {
        this.status = "COMPLETED";
        this.completedAt = LocalDateTime.now();
    }

    public void fail(String message) {
        this.status = "ERROR";
        this.errorMessage = message;
    }
}
