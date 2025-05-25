package com.cos.springjwt.security.repository;

import com.cos.springjwt.security.domain.Refresh;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<Refresh, Long> {

    boolean existsByRefresh(String refresh);

    void deleteByRefresh(String refresh);
}