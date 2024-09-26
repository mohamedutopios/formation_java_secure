package com.example.jwtspringsecurity.repository;

import com.example.jwtspringsecurity.model.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {
}
