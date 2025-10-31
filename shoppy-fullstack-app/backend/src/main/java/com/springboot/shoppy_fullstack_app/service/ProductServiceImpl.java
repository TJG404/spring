package com.springboot.shoppy_fullstack_app.service;

import com.springboot.shoppy_fullstack_app.dto.Product;
import com.springboot.shoppy_fullstack_app.dto.ProductDetailinfo;
import com.springboot.shoppy_fullstack_app.dto.ProductQna;
import com.springboot.shoppy_fullstack_app.dto.ProductReturn;
import com.springboot.shoppy_fullstack_app.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
//@Transactional
public class ProductServiceImpl implements ProductService {
    private ProductRepository productRepository;

    @Autowired
    public ProductServiceImpl(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @Override
    public ProductReturn findReturn() { return productRepository.findReturn(); }

    @Override
    public List<ProductQna> findQna(int pid) {
        return productRepository.findQna(pid);
    }

    @Override
    public ProductDetailinfo findDetailinfo(int pid) {
        return productRepository.findProductDetailinfo(pid);
    }

    @Override
    public Product findByPid(int pid) {
        return productRepository.findByPid(pid);
    }

    @Override
    public List<Product> findAll() {
        List<Product> list = productRepository.findAll();
        return list;
    }
}
