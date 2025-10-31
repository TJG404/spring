package com.springboot.shoppy_fullstack_app.controller;

import com.springboot.shoppy_fullstack_app.dto.KakaoPay;
import com.springboot.shoppy_fullstack_app.dto.KakaoApproveResponse;
import com.springboot.shoppy_fullstack_app.dto.KakaoReadyResponse;
import com.springboot.shoppy_fullstack_app.service.KakaoPayService;
import com.springboot.shoppy_fullstack_app.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/payment")
public class KakaoPayController {

    private final KakaoPayService kakaoPayService;
    private final OrderService orderService;
    private KakaoPay payInfo = null; //KaKaoPay DTO 클래스를 전역으로 선언

    @Autowired
    public KakaoPayController(KakaoPayService kakaoPayService, OrderService orderService) {
        this.kakaoPayService = kakaoPayService;
        this.orderService = orderService;
    }

    /**
     * ✅ 결제 준비 요청 (프론트에서 호출)
     *    카카오페이 결제 ready API 호출
     */
    @PostMapping("/kakao/ready")
    public KakaoReadyResponse paymentKakao(@RequestBody  KakaoPay kakaoPay) {
        //orderId(주문번호) 생성 : UUID 클래스 사용
        payInfo = kakaoPay;   //kakaoPay 객체 주소를 payInfo 복사, 전역으로 확대
        kakaoPay.setOrderId(UUID.randomUUID().toString());
        String TEMP_TID = null;
        KakaoReadyResponse response = kakaoPayService.kakaoPayReady(kakaoPay);

        if (response != null) {
            TEMP_TID = response.getTid(); // 발급받은 TID 저장
        } else {
            System.out.println("결제 준비 실패.");
        }

        return response;
    }

    /**
     * ✅ 결제 성공
     */
    @GetMapping("/qr/success")
    public ResponseEntity<Void> success( @RequestParam String orderId, @RequestParam("pg_token") String pgToken) {

        // 1. tid, userId 조회
        String tid = kakaoPayService.findByTid(orderId);
        String userId = kakaoPayService.findByUserId(orderId);

        // 2. 조회된 tid를 Approve 서비스에 넘겨 최종 승인 요청
        KakaoApproveResponse approve = kakaoPayService.approve(tid, userId, orderId, pgToken);
        System.out.println("Kakao Approve Success --> " + approve);

        // 3. 결제 완료 처리 (DB 상태 업데이트 등)
        //DB 상태 업데이트 - 주문상품을 order, order_detail 테이블에 저장, cart에서는 삭제
        int result = orderService.save(payInfo);
        System.out.println("kakaopay ::: result========>> " + result);

        URI redirect = URI.create("http://localhost:3000/payResult?orderId=" + orderId + "&status=success");
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(redirect);

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }


    /**
     * ✅ 결제 취소 콜백
     */
    @GetMapping("/qr/cancel")
    public ResponseEntity<?> cancel(@RequestParam String orderId) {
        return ResponseEntity.ok(Map.of("status", "CANCEL", "orderId", orderId));
    }

    /**
     * ✅ 결제 실패 콜백
     */
    @GetMapping("/qr/fail")
    public ResponseEntity<?> fail(@RequestParam String orderId) {
        return ResponseEntity.ok(Map.of("status", "FAIL", "orderId", orderId));
    }
}
