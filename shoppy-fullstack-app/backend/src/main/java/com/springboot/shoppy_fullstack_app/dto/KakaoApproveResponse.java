package com.springboot.shoppy_fullstack_app.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class KakaoApproveResponse {
    private String tid;                     //결제 고유 번호, 20자
    private String cid;                     //가맹점 코드
    private String status;                  //결제 상태
    private String partnerOrderId;          //가맹점 주문번호
    private String partnerUserId;           //가맹점 회원아이디
    private String paymentMethodType;       //결제 수단
    private String itemName;                //상품명, 최대 100자
    private int quantity;                   //상품 수량
    private Amount amount;                  //결제 금액
    private String approvedAt;              //결제 승인 시각
    private String cancelAt;                //결제 취소 시각


    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class Amount {
        private Integer total;
        private Integer taxFree;
        private Integer vat;
        private Integer point;
        private Integer discount;
        private Integer greenDeposit;
    }

}



