import { axiosPost } from '../../utils/dataFetch.js';

export const getPayment = async(receiver, paymentInfo, cartList) => {
console.log(cartList);
    const cidList = cartList.map(item => item.cid);
    const qty = cartList.reduce((sum, item) => sum + parseInt(item.qty), 0);
    const { userId } = JSON.parse(localStorage.getItem("loginInfo"));
    const url = "/payment/kakao/ready";  //카카오 QR 코드 호출
    const data = {
        "orderId": "",
        "userId": userId,
        "itemName": cartList[0].name,
        "qty": qty,
        "totalAmount": cartList[0].totalPrice,
        "receiver": receiver,
        "paymentInfo": paymentInfo,
        "cidList": cidList  //[38, 40, 42]
    }

    try {
        const kakaoReadyResult = await axiosPost(url, data);
        console.log("kakaoReadyResult => ", kakaoReadyResult);
        if(kakaoReadyResult.tid) {
            //새로운 페이지 연결
            window.location.href = kakaoReadyResult.next_redirect_pc_url;
        }

    } catch(error) {
        console.log("error :: ", error);
    }
}