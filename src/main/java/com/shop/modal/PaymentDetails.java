package com.shop.modal;

import com.shop.user.domain.PaymentMethod;
import com.shop.user.domain.PaymentStatus;

import lombok.Data;

@Data
public class PaymentDetails {
	
	private PaymentMethod paymentMethod;
	private PaymentStatus status;
	private String paymentId;
	private String razorpayPaymentLinkId;
	private String razorpayPaymentLinkReferenceId;
	private String razorpayPaymentLinkStatus;
	private String razorpayPaymentId​;

}
