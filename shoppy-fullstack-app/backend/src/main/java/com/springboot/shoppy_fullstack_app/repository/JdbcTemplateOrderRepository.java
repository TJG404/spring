package com.springboot.shoppy_fullstack_app.repository;

import com.springboot.shoppy_fullstack_app.dto.KakaoPay;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Repository
public class JdbcTemplateOrderRepository implements OrderRepository{

    private JdbcTemplate jdbcTemplate;
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    public JdbcTemplateOrderRepository(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.namedParameterJdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
    }

    @Override
    public int saveOrders(KakaoPay kakaoPay) {
        String sql = """
            insert into orders(order_code, 
                                member_id, 
                                shipping_fee, 
                                discount_amount, 
                                total_amount, 
                                receiver_name, 
                                receiver_phone, 
                                zipcode, 
                                address1, 
                                address2, memo, odate)
            values(?,?,?,?,?,?,?,?,?,?,?, now())                
            """;
        Object[] params = {
                kakaoPay.getOrderId(),
                kakaoPay.getUserId(),
                kakaoPay.getPaymentInfo().getShippingFee(),
                kakaoPay.getPaymentInfo().getDiscountAmount(),
                kakaoPay.getPaymentInfo().getTotalAmount(),
                kakaoPay.getReceiver().getName(),
                kakaoPay.getReceiver().getPhone(),
                kakaoPay.getReceiver().getZipcode(),
                kakaoPay.getReceiver().getAddress1(),
                kakaoPay.getReceiver().getAddress2(),
                kakaoPay.getReceiver().getMemo()
        };
        return jdbcTemplate.update(sql, params);
    }



    @Override
    public int saveOrderDetail(KakaoPay kakaoPay) {
//        String sql_orders
        String sql = """
            INSERT INTO 
                order_detail(order_code, pid, pname, size, qty, pid_total_price, discount)
            SELECT 
                :orderCode, pid, name AS pname, size, qty, totalPrice AS pid_total_price, 
                :discount
            FROM view_cartlist
            WHERE cid IN (:cidList)
            """;
        Map<String, Object> params = new HashMap<>();
        params.put("orderCode", kakaoPay.getOrderId());
        params.put("discount", kakaoPay.getPaymentInfo().getDiscountAmount());
        params.put("cidList", kakaoPay.getCidList());

        return namedParameterJdbcTemplate.update(sql, params);
    }

    @Override
    public int deleteCartItem(List<Integer> cidList) {
        String sql = """
                delete from cart where cid in (:cidList)
                """;
        Map<String, Object> params = new HashMap<>();
        params.put("cidList", cidList);
        return namedParameterJdbcTemplate.update(sql, params);
    }

}











