curl -X POST https://api.shopfast.io/v1/charges \
  --connect-timeout 30 --retry 3 \
  -H "Authorization: Bearer [[API_KEY|@fake:sk_live_:28]]" \
  -H "X-Internal-Auth: [[SECRET|Hq3Zm8Wv1Ks6Tb0Ny4Jr7Lc2Pf9Dx5]]" \
  -H "Idempotency-Key: 6f1d2c3b-aa41-4e7b-9c2d-7b8e9f0a1b2c" \
  -d '{"customer_email":"[[EMAIL|t.haile@example.org]]","card":"[[PAYMENT_CARD|4242424242424242]]","phone":"[[PHONE|+44 20 7946 0958]]","amount":129900,"currency":"etb"}'
