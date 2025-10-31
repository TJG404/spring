package com.springboot.shoppy_fullstack_app.controller;

import com.springboot.shoppy_fullstack_app.dto.CartItem;
import com.springboot.shoppy_fullstack_app.dto.CartListResponse;
import com.springboot.shoppy_fullstack_app.dto.KakaoPay;
import com.springboot.shoppy_fullstack_app.service.CartService;
import com.springboot.shoppy_fullstack_app.service.KakaoPayService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/cart")
public class CartController {
    private CartService cartService;
    private KakaoPayService kakaoPayService;

    @Autowired
    public CartController(CartService cartService) {
        this.cartService = cartService;
        this.kakaoPayService = kakaoPayService;
    }

    @PostMapping("/deleteItem")
    public int deleteItem(@RequestBody CartItem cartItem) {
        return cartService.deleteItem(cartItem);
    }

    /**
     *  로그인 성공 체크 후 장바구니 리스트 조회
     */
    @PostMapping("/list")
    public ResponseEntity<?> findList(@RequestBody CartItem cartItem,
                                      HttpServletRequest request) {
        HttpSession session = request.getSession(false); //기존 생성 가져오기
        String sid = (String)session.getAttribute("sid");
        String ssid = session.getId();
        ResponseEntity<?> response = null;

        if(ssid != null && sid != null) {
            System.out.println("ssid :: " + ssid + "sid ::" + sid);
            List<CartListResponse> list = cartService.findList(cartItem);
            response = ResponseEntity.ok(list);
        } else {
            response = ResponseEntity.ok(Map.of("result", false));
        }

        return response;
    }

    @PostMapping("/count")
    public CartItem count(@RequestBody CartItem cartItem) {
        return cartService.getCount(cartItem);
    }

    @PostMapping("/updateQty")
    public int  updateQty(@RequestBody CartItem cartItem) {
        System.out.println("updateQty :: " + cartItem);
        return cartService.updateQty(cartItem);
    }

    @PostMapping("/checkQty")
    public CartItem checkQty(@RequestBody CartItem cartItem) {
        System.out.println("checkQty" + cartItem.getPid() + cartItem.getSize() + cartItem.getId());
        return cartService.checkQty(cartItem);
    }

    @PostMapping("/add")
    public int add(@RequestBody CartItem cartItem) {
        return cartService.add(cartItem);
    }
}
