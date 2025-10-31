package com.springboot.shoppy_fullstack_app.service;

import com.springboot.shoppy_fullstack_app.dto.KakaoPay;
import com.springboot.shoppy_fullstack_app.repository.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
//@Transactional
public class OrderServiceImpl implements OrderService {
    private OrderRepository orderRepository;

    @Autowired
    public OrderServiceImpl(OrderRepository orderRepository){
        this.orderRepository = orderRepository;
    }

    @Override
    @Transactional  //DB연동로직을 하나의 트랜잭션으로 관리
    public int save(KakaoPay kakaoPay) {
        int rows = orderRepository.saveOrders(kakaoPay);
        if(!(rows == 1)) System.out.println("결제 실패!!");

        int rows_detail = orderRepository.saveOrderDetail(kakaoPay);
        if(!(rows_detail < 1)) System.out.println("결제 실패!!");

        int rows_cart = orderRepository.deleteCartItem(kakaoPay.getCidList());

        return rows;
    }
}
