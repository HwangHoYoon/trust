package com.fast.trust.scan.repository;


import com.fast.trust.scan.entity.ScanDetail;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanDetailRepository extends JpaRepository<ScanDetail, Long> {

    List<ScanDetail> findByScanId(String scanId);
}