"""
core/intelligence/platform_profiler.py
Platform detection and attack surface profiling.
Works with both known platforms (Spotify, Stripe, PayPal, Wise,
Open Banking, UBA, Shopify, WooCommerce, etc.) and unknown platforms
detected via fingerprinting signals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional






PLATFORM_STREAMING   = "STREAMING"
PLATFORM_FINTECH     = "FINTECH"
PLATFORM_BANKING     = "BANKING"
PLATFORM_ECOMMERCE   = "ECOMMERCE"
PLATFORM_SAAS        = "SAAS"
PLATFORM_UNKNOWN     = "UNKNOWN"


KNOWN_SPOTIFY        = "SPOTIFY"
KNOWN_STRIPE         = "STRIPE"
KNOWN_PAYPAL         = "PAYPAL"
KNOWN_WISE           = "WISE"
KNOWN_OPENBANKING    = "OPEN_BANKING"
KNOWN_UBA            = "UBA"
KNOWN_SHOPIFY        = "SHOPIFY"
KNOWN_WOOCOMMERCE    = "WOOCOMMERCE"
KNOWN_REVOLUT        = "REVOLUT"
KNOWN_SQUARE         = "SQUARE"
KNOWN_BRAINTREE      = "BRAINTREE"
KNOWN_ADYEN          = "ADYEN"
KNOWN_PLAID          = "PLAID"
KNOWN_FLUTTERWAVE    = "FLUTTERWAVE"
KNOWN_PAYSTACK       = "PAYSTACK"
KNOWN_MONZO          = "MONZO"
KNOWN_STARLING       = "STARLING"
KNOWN_TRUELAYER      = "TRUELAYER"






@dataclass
class PlatformProfile:
    platform_type:          str
    known_platform:         Optional[str]
    confidence:             int
    indicators:             list[str]
    priority_modules:       list[str]
    skip_modules:           list[str]
    discovery_seeds:        list[str]
    high_value_paths:       list[str]
    known_api_structure:    dict
    attack_config:          dict
    domain_chains:          list[str]






KNOWN_PLATFORMS: dict[str, dict] = {

    KNOWN_SPOTIFY: {
        "type": PLATFORM_STREAMING,
        "host_patterns": [
            r"api\.spotify\.com",
            r"accounts\.spotify\.com",
            r"spclient\.wg\.spotify\.com",
            r"audio.*\.spotify\.com",
        ],
        "header_signals": {
            "x-content-type-options": "nosniff",
        },
        "path_signals": [
            "/v1/me", "/v1/tracks", "/v1/albums", "/v1/playlists",
            "/v1/search", "/v1/audio-features",
        ],
        "body_signals": [
            r'"track_number"', r'"disc_number"', r'"duration_ms"',
            r'"preview_url"', r'"is_playable"', r'"external_ids"',
        ],
        "priority_modules": [
            "subscription_scope_probe", "stream_count_manipulator",
            "download_token_replay", "device_limit_bypass",
            "premium_endpoint_access", "family_plan_abuse",
        ],
        "skip_modules": [
            "price_manipulation", "negative_quantity", "coupon_stacking",
            "webhook_forgery", "mandate_forgery",
        ],
        "high_value_paths": [
            "/v1/me/player",
            "/v1/me/player/play",
            "/v1/me/player/currently-playing",
            "/v1/me/tracks",
            "/v1/me/albums",
            "/v1/me/shows",
            "/v1/me/episodes",
            "/v1/me/following",
            "/v1/users/{id}/playlists",
            "/v1/browse/featured-playlists",
            "/v1/me/player/devices",
            "/v1/me/player/queue",
            "/v1/me/player/recently-played",
            "/v1/me/top/tracks",
            "/v1/me/top/artists",
            "/v1/recommendations",
            "/v1/audio-analysis/{id}",
        ],
        "discovery_seeds": [
            "stream", "track", "album", "playlist", "artist", "podcast",
            "premium", "subscription", "download", "offline", "device",
            "play", "skip", "queue", "radio", "listen", "audio",
            "royalty", "analytics", "embed", "connect", "lyrics",
            "preview", "free", "shuffle", "repeat", "volume",
        ],
        "known_api_structure": {
            "base_url": "https://api.spotify.com",
            "auth_url": "https://accounts.spotify.com/api/token",
            "auth_type": "OAuth2_Bearer",
            "scopes": [
                "user-read-private", "user-read-email",
                "user-library-read", "user-library-modify",
                "playlist-read-private", "playlist-modify-public",
                "streaming", "user-read-playback-state",
                "user-modify-playback-state", "user-read-currently-playing",
            ],
            "rate_limit_header": "retry-after",
            "pagination": {"limit": 50, "offset": 0},
        },
        "attack_config": {
            "test_free_vs_premium": True,
            "test_scope_enforcement": True,
            "test_play_count_manipulation": True,
            "test_download_token_replay": True,
            "check_preview_url_access": True,
        },
        "domain_chains": ["CHAIN_STREAMING_1", "CHAIN_STREAMING_2"],
    },

    KNOWN_STRIPE: {
        "type": PLATFORM_FINTECH,
        "host_patterns": [
            r"api\.stripe\.com",
            r"dashboard\.stripe\.com",
            r"connect\.stripe\.com",
        ],
        "header_signals": {
            "stripe-version": "",
            "request-id": "req_",
        },
        "path_signals": [
            "/v1/charges", "/v1/customers", "/v1/payment_intents",
            "/v1/refunds", "/v1/subscriptions", "/v1/invoices",
        ],
        "body_signals": [
            r'"object":\s*"charge"', r'"livemode":', r'"stripe_id"',
            r'"payment_method_types"', r'"amount_capturable"',
        ],
        "priority_modules": [
            "amount_sign_flip", "idempotency_abuse", "refund_overflow",
            "webhook_forgery", "fee_bypass", "currency_confusion",
            "connect_account_idor",
        ],
        "skip_modules": [
            "stream_count_manipulator", "device_limit_bypass",
            "download_token_replay", "family_plan_abuse",
        ],
        "high_value_paths": [
            "/v1/charges",
            "/v1/charges/{id}/refunds",
            "/v1/payment_intents",
            "/v1/payment_intents/{id}/confirm",
            "/v1/payment_intents/{id}/capture",
            "/v1/payment_intents/{id}/cancel",
            "/v1/refunds",
            "/v1/customers",
            "/v1/customers/{id}",
            "/v1/subscriptions",
            "/v1/invoices/{id}/pay",
            "/v1/transfers",
            "/v1/payouts",
            "/v1/accounts",
            "/v1/accounts/{id}",
            "/v1/webhook_endpoints",
            "/v1/disputes",
            "/v1/balance",
            "/v1/balance_transactions",
        ],
        "discovery_seeds": [
            "charge", "payment", "intent", "refund", "capture",
            "transfer", "payout", "subscription", "invoice", "customer",
            "connect", "account", "balance", "dispute", "webhook",
            "idempotency", "fee", "tax", "coupon", "promo",
        ],
        "known_api_structure": {
            "base_url": "https://api.stripe.com",
            "auth_type": "Basic_SecretKey",
            "idempotency_header": "Idempotency-Key",
            "version_header": "Stripe-Version",
            "webhook_sig_header": "Stripe-Signature",
        },
        "attack_config": {
            "test_negative_amounts": True,
            "test_idempotency_replay": True,
            "test_refund_overflow": True,
            "test_webhook_signature_bypass": True,
            "test_connect_account_idor": True,
            "test_fee_bypass": True,
        },
        "domain_chains": ["CHAIN_FINTECH_1", "CHAIN_FINTECH_2"],
    },

    KNOWN_PAYPAL: {
        "type": PLATFORM_FINTECH,
        "host_patterns": [
            r"api\.paypal\.com",
            r"api-m\.paypal\.com",
            r"api\.sandbox\.paypal\.com",
        ],
        "header_signals": {
            "paypal-debug-id": "",
            "application-id": "",
        },
        "path_signals": [
            "/v1/payments/payment", "/v2/checkout/orders",
            "/v1/billing/subscriptions", "/v2/payments/captures",
        ],
        "body_signals": [
            r'"purchase_units"', r'"payer"', r'"payee"',
            r'"payment_source"', r'"funding_source"',
        ],
        "priority_modules": [
            "amount_sign_flip", "currency_confusion", "refund_overflow",
            "idempotency_abuse", "webhook_forgery", "fee_bypass",
            "paypal_order_manipulation",
        ],
        "skip_modules": [
            "stream_count_manipulator", "device_limit_bypass",
            "mandate_forgery",
        ],
        "high_value_paths": [
            "/v2/checkout/orders",
            "/v2/checkout/orders/{id}/capture",
            "/v2/checkout/orders/{id}/authorize",
            "/v2/payments/captures/{id}/refund",
            "/v2/payments/authorizations/{id}/capture",
            "/v1/billing/subscriptions",
            "/v1/billing/subscriptions/{id}",
            "/v1/billing/subscriptions/{id}/cancel",
            "/v1/invoicing/invoices",
            "/v1/payments/payouts",
            "/v1/payments/payouts-item/{id}/cancel",
            "/v2/vault/payment-tokens",
            "/v1/reporting/transactions",
        ],
        "discovery_seeds": [
            "order", "capture", "authorize", "refund", "payout",
            "subscription", "billing", "invoice", "vault", "token",
            "payment", "source", "method", "dispute", "webhook",
        ],
        "known_api_structure": {
            "base_url": "https://api-m.paypal.com",
            "auth_type": "OAuth2_ClientCredentials",
            "token_endpoint": "/v1/oauth2/token",
            "webhook_sig_headers": [
                "paypal-transmission-id", "paypal-cert-url",
                "paypal-auth-algo", "paypal-transmission-sig",
            ],
        },
        "attack_config": {
            "test_negative_amounts": True,
            "test_currency_confusion": True,
            "test_refund_overflow": True,
            "test_webhook_bypass": True,
            "test_order_amount_override": True,
        },
        "domain_chains": ["CHAIN_FINTECH_1", "CHAIN_FINTECH_2"],
    },

    KNOWN_WISE: {
        "type": PLATFORM_FINTECH,
        "host_patterns": [
            r"api\.transferwise\.com",
            r"api\.wise\.com",
            r"sandbox\.transferwise\.tech",
        ],
        "header_signals": {
            "x-2fa-approval": "",
        },
        "path_signals": [
            "/v1/profiles", "/v1/accounts", "/v1/transfers",
            "/v3/quotes", "/v1/borderless-accounts",
        ],
        "body_signals": [
            r'"sourceAmount"', r'"targetAmount"', r'"sourceCurrency"',
            r'"targetCurrency"', r'"rate"', r'"profileId"',
        ],
        "priority_modules": [
            "amount_sign_flip", "currency_confusion", "transfer_idor",
            "fee_bypass", "kyc_bypass", "sca_bypass",
            "idempotency_abuse", "refund_overflow",
        ],
        "skip_modules": [
            "stream_count_manipulator", "coupon_stacking",
            "device_limit_bypass",
        ],
        "high_value_paths": [
            "/v1/profiles/{profileId}/transfers",
            "/v1/transfers",
            "/v1/transfers/{id}/cancel",
            "/v3/quotes",
            "/v1/borderless-accounts/{id}/statement",
            "/v1/borderless-accounts/{id}/top-up",
            "/v1/accounts",
            "/v1/profiles/{id}/verification-documents",
            "/v2/profiles/{profileId}/transfers",
            "/v1/simulation/transfers/{id}/processing",
        ],
        "discovery_seeds": [
            "transfer", "quote", "recipient", "profile", "account",
            "borderless", "statement", "kyc", "verification", "sca",
            "2fa", "approval", "cancel", "refund", "fee", "rate",
            "currency", "source", "target", "batch",
        ],
        "known_api_structure": {
            "base_url": "https://api.wise.com",
            "auth_type": "Bearer_PersonalToken",
            "sca_header": "x-2fa-approval",
            "profile_types": ["personal", "business"],
        },
        "attack_config": {
            "test_negative_amounts": True,
            "test_currency_confusion": True,
            "test_sca_bypass": True,
            "test_profile_idor": True,
            "test_statement_idor": True,
        },
        "domain_chains": ["CHAIN_FINTECH_1", "CHAIN_BANKING_1"],
    },

    KNOWN_OPENBANKING: {
        "type": PLATFORM_BANKING,
        "host_patterns": [
            r"api\..*\.co\.uk/open-banking",
            r".*\.openbankingplatform\.com",
            r"rs1\..*\.co\.uk",
            r"ob\..*\.com",
            r"api\.truelayer\.com",
            r"auth\.truelayer\.com",
        ],
        "header_signals": {
            "x-fapi-interaction-id": "",
            "x-fapi-financial-id": "",
        },
        "path_signals": [
            "/open-banking/v3", "/aisp/accounts",
            "/pisp/domestic-payments", "/cbpii/funds-confirmation",
        ],
        "body_signals": [
            r'"OBReadAccount"', r'"InstructedAmount"', r'"CreditorAccount"',
            r'"DebtorAccount"', r'"ConsentId"', r'"Risk"',
        ],
        "priority_modules": [
            "consent_scope_overflow", "account_idor", "statement_idor",
            "payment_idor", "mandate_forgery", "beneficiary_bypass",
            "transaction_limit_reset", "pisp_amount_manipulation",
        ],
        "skip_modules": [
            "stream_count_manipulator", "coupon_stacking",
            "device_limit_bypass", "download_token_replay",
        ],
        "high_value_paths": [
            "/open-banking/v3.1/aisp/accounts",
            "/open-banking/v3.1/aisp/accounts/{AccountId}",
            "/open-banking/v3.1/aisp/accounts/{AccountId}/balances",
            "/open-banking/v3.1/aisp/accounts/{AccountId}/transactions",
            "/open-banking/v3.1/aisp/accounts/{AccountId}/statements",
            "/open-banking/v3.1/aisp/accounts/{AccountId}/direct-debits",
            "/open-banking/v3.1/aisp/accounts/{AccountId}/standing-orders",
            "/open-banking/v3.1/pisp/domestic-payments",
            "/open-banking/v3.1/pisp/domestic-payment-consents",
            "/open-banking/v3.1/pisp/international-payments",
            "/open-banking/v3.1/cbpii/funds-confirmations",
            "/open-banking/v3.1/aisp/beneficiaries",
        ],
        "discovery_seeds": [
            "account", "balance", "transaction", "statement", "payment",
            "consent", "domestic", "international", "standing-order",
            "direct-debit", "beneficiary", "funds", "confirmation",
            "aisp", "pisp", "cbpii", "fapi", "sort-code", "iban",
        ],
        "known_api_structure": {
            "auth_type": "OAuth2_FAPI",
            "consent_header": "x-fapi-interaction-id",
            "signing_header": "x-jws-signature",
            "versions": ["v3.0", "v3.1", "v3.1.2", "v3.1.6", "v3.1.10"],
        },
        "attack_config": {
            "test_consent_scope_overflow": True,
            "test_account_idor": True,
            "test_cross_institution_idor": True,
            "test_payment_amount_manipulation": True,
        },
        "domain_chains": ["CHAIN_BANKING_1", "CHAIN_BANKING_2"],
    },

    KNOWN_UBA: {
        "type": PLATFORM_BANKING,
        "host_patterns": [
            r"api\.ubagroup\.com",
            r".*\.ubagroup\.com",
            r"developer\.ubagroup\.com",
        ],
        "header_signals": {},
        "path_signals": [
            "/api/v1/accounts", "/api/v1/transfers",
            "/api/v1/payments", "/api/v1/beneficiaries",
        ],
        "body_signals": [
            r'"accountNumber"', r'"bankCode"', r'"narration"',
            r'"transactionRef"', r'"sourceAccount"',
        ],
        "priority_modules": [
            "amount_sign_flip", "account_idor", "transfer_idor",
            "beneficiary_bypass", "transaction_limit_reset",
            "statement_idor", "kyc_bypass", "fee_bypass",
        ],
        "skip_modules": [
            "stream_count_manipulator", "download_token_replay",
            "device_limit_bypass", "coupon_stacking",
        ],
        "high_value_paths": [
            "/api/v1/accounts",
            "/api/v1/accounts/{accountNumber}",
            "/api/v1/accounts/{accountNumber}/balance",
            "/api/v1/accounts/{accountNumber}/transactions",
            "/api/v1/accounts/{accountNumber}/statement",
            "/api/v1/transfers",
            "/api/v1/transfers/interbank",
            "/api/v1/transfers/intrabank",
            "/api/v1/beneficiaries",
            "/api/v1/payments/bills",
            "/api/v1/payments/airtime",
            "/api/v1/payments/data",
            "/api/v1/cards",
            "/api/v1/loans",
        ],
        "discovery_seeds": [
            "account", "transfer", "payment", "beneficiary", "card",
            "loan", "statement", "balance", "transaction", "airtime",
            "data", "bill", "kyc", "bvn", "nin", "otp", "pin",
            "intrabank", "interbank", "narration", "reference",
        ],
        "known_api_structure": {
            "auth_type": "Bearer_JWT",
            "otp_required": True,
            "transaction_ref_field": "transactionRef",
        },
        "attack_config": {
            "test_negative_amounts": True,
            "test_account_number_idor": True,
            "test_otp_bypass": True,
            "test_beneficiary_forgery": True,
            "test_statement_idor": True,
        },
        "domain_chains": ["CHAIN_BANKING_1", "CHAIN_FINTECH_1"],
    },

    KNOWN_SHOPIFY: {
        "type": PLATFORM_ECOMMERCE,
        "host_patterns": [
            r".*\.myshopify\.com",
            r".*\.shopify\.com",
            r"app\.shopify\.com",
        ],
        "header_signals": {
            "x-shopify-shop-api-call-limit": "",
            "x-request-id": "",
        },
        "path_signals": [
            "/admin/api/", "/api/storefront/",
            "/api/graphql", "/admin/orders",
        ],
        "body_signals": [
            r'"shopify_payments"', r'"fulfillment_service"',
            r'"variant_id"', r'"line_items"', r'"financial_status"',
        ],
        "priority_modules": [
            "cart_price_injection", "inventory_bypass",
            "discount_code_generation", "order_status_manipulation",
            "guest_order_idor", "wholesale_price_leak",
            "affiliate_commission_fraud", "flash_sale_replay",
        ],
        "skip_modules": [
            "stream_count_manipulator", "device_limit_bypass",
            "download_token_replay", "mandate_forgery",
            "consent_scope_overflow",
        ],
        "high_value_paths": [
            "/admin/api/2024-01/orders.json",
            "/admin/api/2024-01/orders/{id}.json",
            "/admin/api/2024-01/customers.json",
            "/admin/api/2024-01/customers/{id}.json",
            "/admin/api/2024-01/products.json",
            "/admin/api/2024-01/price_rules.json",
            "/admin/api/2024-01/discounts.json",
            "/admin/api/2024-01/gift_cards.json",
            "/admin/api/2024-01/checkouts.json",
            "/admin/api/2024-01/draft_orders.json",
            "/admin/api/2024-01/inventory_items.json",
            "/admin/api/2024-01/refunds.json",
            "/api/storefront/graphql",
            "/api/2024-01/graphql.json",
        ],
        "discovery_seeds": [
            "cart", "checkout", "order", "product", "variant", "inventory",
            "discount", "price", "coupon", "gift", "refund", "return",
            "fulfillment", "shipping", "customer", "collection", "review",
            "wishlist", "affiliate", "referral", "wholesale", "draft",
        ],
        "known_api_structure": {
            "auth_types": ["Private_App_Password", "OAuth2", "Storefront_Token"],
            "rate_limit_header": "x-shopify-shop-api-call-limit",
            "graphql_endpoint": "/api/2024-01/graphql.json",
            "rest_version": "2024-01",
        },
        "attack_config": {
            "test_price_manipulation": True,
            "test_inventory_bypass": True,
            "test_discount_code_brute": True,
            "test_order_idor": True,
            "test_draft_order_price": True,
        },
        "domain_chains": ["CHAIN_ECOMMERCE_1", "CHAIN_ECOMMERCE_2"],
    },

    KNOWN_WOOCOMMERCE: {
        "type": PLATFORM_ECOMMERCE,
        "host_patterns": [
            r".*\?wc-api=",
            r".*/wp-json/wc/",
            r".*/wc-auth/",
        ],
        "header_signals": {
            "x-wc-webhook-source": "",
            "x-woocommerce-": "",
        },
        "path_signals": [
            "/wp-json/wc/v3/", "/wp-json/wc/v2/",
            "/wc-api/v3/", "?wc-api=",
        ],
        "body_signals": [
            r'"woocommerce"', r'"line_items".*"product_id"',
            r'"coupon_lines"', r'"shipping_lines"', r'"fee_lines"',
        ],
        "priority_modules": [
            "cart_price_injection", "inventory_bypass",
            "coupon_stacking", "order_status_manipulation",
            "guest_order_idor", "woocommerce_rest_idor",
            "discount_code_generation", "refund_overflow",
        ],
        "skip_modules": [
            "stream_count_manipulator", "device_limit_bypass",
            "download_token_replay", "mandate_forgery",
        ],
        "high_value_paths": [
            "/wp-json/wc/v3/orders",
            "/wp-json/wc/v3/orders/{id}",
            "/wp-json/wc/v3/customers",
            "/wp-json/wc/v3/customers/{id}",
            "/wp-json/wc/v3/products",
            "/wp-json/wc/v3/coupons",
            "/wp-json/wc/v3/refunds",
            "/wp-json/wc/v3/payment-gateways",
            "/wp-json/wc/v3/shipping-zones",
            "/wp-json/wc/v3/reports/sales",
            "/wp-json/wc/v3/reports/top-sellers",
            "/wp-json/wc/v3/system-status",
            "/wp-json/wp/v2/users",
        ],
        "discovery_seeds": [
            "order", "product", "customer", "coupon", "refund",
            "shipping", "payment", "gateway", "webhook", "report",
            "cart", "checkout", "variation", "category", "tag",
            "review", "subscription", "membership",
        ],
        "known_api_structure": {
            "auth_types": ["Consumer_Key_Secret", "OAuth1"],
            "rest_namespace": "wc/v3",
            "graphql": False,
        },
        "attack_config": {
            "test_price_manipulation": True,
            "test_coupon_stacking": True,
            "test_order_idor": True,
            "test_customer_idor": True,
            "test_rest_api_auth_bypass": True,
        },
        "domain_chains": ["CHAIN_ECOMMERCE_1", "CHAIN_ECOMMERCE_2"],
    },

    KNOWN_REVOLUT: {
        "type": PLATFORM_FINTECH,
        "host_patterns": [
            r"api\.revolut\.com",
            r"merchant\.revolut\.com",
            r"sandbox-merchant\.revolut\.com",
        ],
        "header_signals": {
            "revolut-request-id": "",
        },
        "path_signals": [
            "/api/1/", "/merchant/api/1/",
            "/api/orders", "/api/customers",
        ],
        "body_signals": [
            r'"revolut_pay"', r'"currency"', r'"counterpart"',
            r'"merchant"', r'"card_number"',
        ],
        "priority_modules": [
            "amount_sign_flip", "currency_confusion", "idempotency_abuse",
            "refund_overflow", "fee_bypass", "transfer_idor",
        ],
        "skip_modules": [
            "stream_count_manipulator", "mandate_forgery",
            "device_limit_bypass",
        ],
        "high_value_paths": [
            "/api/1/accounts",
            "/api/1/transactions",
            "/api/1/pay",
            "/api/1/transfer",
            "/api/1/exchange",
            "/merchant/api/1/orders",
            "/merchant/api/1/orders/{id}/refund",
            "/merchant/api/1/customers",
            "/api/1/cards",
            "/api/1/user",
        ],
        "discovery_seeds": [
            "account", "transaction", "transfer", "exchange", "pay",
            "card", "merchant", "order", "refund", "customer",
            "top-up", "pocket", "savings", "crypto", "stock",
        ],
        "known_api_structure": {
            "base_url": "https://api.revolut.com",
            "auth_type": "Bearer_JWT",
            "merchant_base": "https://merchant.revolut.com",
        },
        "attack_config": {
            "test_negative_amounts": True,
            "test_currency_confusion": True,
            "test_cross_account_transfer": True,
        },
        "domain_chains": ["CHAIN_FINTECH_1", "CHAIN_FINTECH_2"],
    },

    KNOWN_FLUTTERWAVE: {
        "type": PLATFORM_FINTECH,
        "host_patterns": [
            r"api\.flutterwave\.com",
            r"ravesandboxapi\.flutterwave\.com",
        ],
        "header_signals": {},
        "path_signals": [
            "/v3/payments", "/v3/charges", "/v3/transfers",
            "/v3/settlements", "/v3/subaccounts",
        ],
        "body_signals": [
            r'"flw_ref"', r'"tx_ref"', r'"currency"',
            r'"amount"', r'"customer"', r'"meta"',
        ],
        "priority_modules": [
            "amount_sign_flip", "currency_confusion", "webhook_forgery",
            "subaccount_idor", "settlement_manipulation", "fee_bypass",
        ],
        "skip_modules": [
            "stream_count_manipulator", "device_limit_bypass",
        ],
        "high_value_paths": [
            "/v3/payments",
            "/v3/charges?type=mobile_money_ghana",
            "/v3/transfers",
            "/v3/settlements",
            "/v3/subaccounts",
            "/v3/transactions",
            "/v3/transactions/{id}/verify",
            "/v3/refunds",
            "/v3/virtual-accounts",
            "/v3/bills",
        ],
        "discovery_seeds": [
            "payment", "charge", "transfer", "settlement", "subaccount",
            "transaction", "refund", "webhook", "virtual", "bill",
            "airtime", "data", "subscription", "plan", "customer",
        ],
        "known_api_structure": {
            "base_url": "https://api.flutterwave.com",
            "auth_type": "Bearer_SecretKey",
            "webhook_hash_header": "verif-hash",
        },
        "attack_config": {
            "test_negative_amounts": True,
            "test_webhook_hash_bypass": True,
            "test_subaccount_idor": True,
            "test_transaction_verification_bypass": True,
        },
        "domain_chains": ["CHAIN_FINTECH_1"],
    },

    KNOWN_PAYSTACK: {
        "type": PLATFORM_FINTECH,
        "host_patterns": [
            r"api\.paystack\.co",
        ],
        "header_signals": {},
        "path_signals": [
            "/transaction/initialize", "/transaction/verify",
            "/charge", "/refund", "/transfer",
        ],
        "body_signals": [
            r'"authorization_code"', r'"access_code"',
            r'"reference"', r'"channel"', r'"gateway_response"',
        ],
        "priority_modules": [
            "amount_sign_flip", "webhook_forgery", "idempotency_abuse",
            "refund_overflow", "transfer_idor", "fee_bypass",
        ],
        "skip_modules": [
            "stream_count_manipulator", "device_limit_bypass",
        ],
        "high_value_paths": [
            "/transaction/initialize",
            "/transaction/verify/{reference}",
            "/transaction",
            "/charge",
            "/refund",
            "/transfer",
            "/transfer/bulk",
            "/transferrecipient",
            "/subscription",
            "/plan",
            "/customer",
            "/subaccount",
            "/settlement",
        ],
        "discovery_seeds": [
            "transaction", "charge", "refund", "transfer", "subscription",
            "plan", "customer", "subaccount", "settlement", "invoice",
            "product", "page", "recipient", "balance", "webhook",
        ],
        "known_api_structure": {
            "base_url": "https://api.paystack.co",
            "auth_type": "Bearer_SecretKey",
            "webhook_ip_whitelist": True,
        },
        "attack_config": {
            "test_negative_amounts": True,
            "test_reference_replay": True,
            "test_webhook_ip_bypass": True,
            "test_subaccount_idor": True,
        },
        "domain_chains": ["CHAIN_FINTECH_1"],
    },
}






_STREAMING_SIGNALS = [
    (r"subscription|premium|free.tier|plan", 20, PLATFORM_STREAMING),
    (r"track|album|playlist|artist|podcast", 20, PLATFORM_STREAMING),
    (r"stream|audio|video|media|play|pause", 15, PLATFORM_STREAMING),
    (r"duration_ms|preview_url|is_playable",  25, PLATFORM_STREAMING),
    (r"Stripe\.js|braintree|paypal\.com",    -10, PLATFORM_STREAMING),
]

_FINTECH_SIGNALS = [
    (r"amount|currency|transfer|payment|charge|refund", 20, PLATFORM_FINTECH),
    (r"wallet|balance|payout|settlement|ledger",        20, PLATFORM_FINTECH),
    (r"idempotency|idem.key|x-idempotency",             30, PLATFORM_FINTECH),
    (r"stripe|paypal|braintree|adyen|wise",             25, PLATFORM_FINTECH),
    (r"kyc|aml|sanctions|compliance|screening",        25, PLATFORM_FINTECH),
    (r"webhook.*signature|hmac.*sha|x-hub-signature",  20, PLATFORM_FINTECH),
]

_BANKING_SIGNALS = [
    (r"sort.code|iban|swift|bic|routing.number",       30, PLATFORM_BANKING),
    (r"open.banking|fapi|aisp|pisp|cbpii",             40, PLATFORM_BANKING),
    (r"consent|mandate|standing.order|direct.debit",   25, PLATFORM_BANKING),
    (r"x-fapi|x-jws-signature|financial.id",           35, PLATFORM_BANKING),
    (r"account.number|sort.code|bank.code",             20, PLATFORM_BANKING),
    (r"psd2|sca|strong.customer|2fa.approval",          30, PLATFORM_BANKING),
]

_ECOMMERCE_SIGNALS = [
    (r"cart|checkout|order|product|inventory",         20, PLATFORM_ECOMMERCE),
    (r"sku|variant|line.item|shipping|fulfilment",     20, PLATFORM_ECOMMERCE),
    (r"coupon|discount|promo|voucher|gift.card",       15, PLATFORM_ECOMMERCE),
    (r"shopify|woocommerce|magento|prestashop",        30, PLATFORM_ECOMMERCE),
    (r"financial.status|fulfillment.status|refund",    20, PLATFORM_ECOMMERCE),
    (r"wp-json/wc|x-shopify|x-wc-webhook",            35, PLATFORM_ECOMMERCE),
]






class PlatformProfiler:
    """
    Detects known platforms by host/path/header/body pattern matching,
    then falls back to unknown-platform fingerprinting for custom stacks.
    Integrates with BLFScanner and HiddenEndpointHunter.
    """

    def profile(
        self,
        target_url:     str,
        response_headers: dict,
        response_body:  str,
        discovered_paths: list[str],
    ) -> PlatformProfile:
        known = self._match_known(target_url, response_headers,
                                  response_body, discovered_paths)
        if known:
            return known
        return self._fingerprint_unknown(
            target_url, response_headers, response_body, discovered_paths
        )

    def _match_known(
        self,
        url:      str,
        headers:  dict,
        body:     str,
        paths:    list[str],
    ) -> Optional[PlatformProfile]:
        header_str = " ".join(f"{k.lower()}: {v.lower()}"
                              for k, v in headers.items())
        path_str   = " ".join(paths)
        body_lower = body.lower()[:3000]
        combined   = f"{url} {header_str} {path_str} {body_lower}"

        best_score   = 0
        best_name    = None
        best_data    = None
        indicators   = []

        for platform_name, pdata in KNOWN_PLATFORMS.items():
            score = 0
            hits  = []

            for pattern in pdata.get("host_patterns", []):
                if re.search(pattern, url, re.I):
                    score += 50
                    hits.append(f"host matches {pattern}")

            for hdr, val in pdata.get("header_signals", {}).items():
                if hdr.lower() in header_str:
                    score += 30
                    hits.append(f"header: {hdr}")

            for path in pdata.get("path_signals", []):
                if path in path_str or path in url:
                    score += 20
                    hits.append(f"path: {path}")

            for sig in pdata.get("body_signals", []):
                if re.search(sig, body_lower, re.I):
                    score += 15
                    hits.append(f"body: {sig[:30]}")

            if score > best_score:
                best_score  = score
                best_name   = platform_name
                best_data   = pdata
                indicators  = hits

        if best_score >= 30 and best_data:
            return PlatformProfile(
                platform_type     = best_data["type"],
                known_platform    = best_name,
                confidence        = min(100, best_score),
                indicators        = indicators,
                priority_modules  = best_data.get("priority_modules", []),
                skip_modules      = best_data.get("skip_modules", []),
                discovery_seeds   = best_data.get("discovery_seeds", []),
                high_value_paths  = best_data.get("high_value_paths", []),
                known_api_structure = best_data.get("known_api_structure", {}),
                attack_config     = best_data.get("attack_config", {}),
                domain_chains     = best_data.get("domain_chains", []),
            )

        return None

    def _fingerprint_unknown(
        self,
        url:     str,
        headers: dict,
        body:    str,
        paths:   list[str],
    ) -> PlatformProfile:
        combined = f"{url} {' '.join(paths)} {body[:3000]}".lower()
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        full_text  = combined + " " + header_str

        scores: dict[str, int] = {
            PLATFORM_STREAMING: 0,
            PLATFORM_FINTECH:   0,
            PLATFORM_BANKING:   0,
            PLATFORM_ECOMMERCE: 0,
        }
        indicators: list[str] = []

        for signal_list in [
            _STREAMING_SIGNALS,
            _FINTECH_SIGNALS,
            _BANKING_SIGNALS,
            _ECOMMERCE_SIGNALS,
        ]:
            for pattern, weight, ptype in signal_list:
                if re.search(pattern, full_text, re.I):
                    scores[ptype] = max(0, scores[ptype] + weight)
                    indicators.append(f"{ptype}: {pattern[:30]}")

        best_type  = max(scores, key=scores.__getitem__)
        best_score = scores[best_type]

        if best_score < 15:
            best_type = PLATFORM_UNKNOWN

        return PlatformProfile(
            platform_type       = best_type,
            known_platform      = None,
            confidence          = min(100, best_score),
            indicators          = indicators[:10],
            priority_modules    = _default_priority_modules(best_type),
            skip_modules        = _default_skip_modules(best_type),
            discovery_seeds     = _default_seeds(best_type),
            high_value_paths    = [],
            known_api_structure = {},
            attack_config       = _default_attack_config(best_type),
            domain_chains       = _default_chains(best_type),
        )






def _default_priority_modules(ptype: str) -> list[str]:
    return {
        PLATFORM_STREAMING: [
            "subscription_scope_probe", "premium_endpoint_access",
            "idor_bola", "bopla",
        ],
        PLATFORM_FINTECH: [
            "amount_sign_flip", "idempotency_abuse", "refund_overflow",
            "webhook_forgery", "currency_confusion", "fee_bypass",
        ],
        PLATFORM_BANKING: [
            "account_idor", "consent_scope_overflow", "statement_idor",
            "beneficiary_bypass", "transaction_limit_reset",
        ],
        PLATFORM_ECOMMERCE: [
            "cart_price_injection", "inventory_bypass", "coupon_stacking",
            "order_status_manipulation", "guest_order_idor",
        ],
        PLATFORM_UNKNOWN: [
            "idor_bola", "mass_assignment", "privilege_escalation",
            "bopla", "race_condition",
        ],
    }.get(ptype, [])


def _default_skip_modules(ptype: str) -> list[str]:
    base_skip = []
    if ptype in (PLATFORM_FINTECH, PLATFORM_BANKING):
        base_skip += ["stream_count_manipulator", "device_limit_bypass",
                      "download_token_replay", "coupon_stacking"]
    if ptype == PLATFORM_STREAMING:
        base_skip += ["mandate_forgery", "beneficiary_bypass",
                      "webhook_forgery", "cart_price_injection"]
    return base_skip


def _default_seeds(ptype: str) -> list[str]:
    from core.intelligence.platform_attack_modules import PLATFORM_SEEDS
    return PLATFORM_SEEDS.get(ptype, PLATFORM_SEEDS.get(PLATFORM_UNKNOWN, []))


def _default_attack_config(ptype: str) -> dict:
    return {
        PLATFORM_STREAMING: {"test_free_vs_premium": True, "test_scope_enforcement": True},
        PLATFORM_FINTECH:   {"test_negative_amounts": True, "test_refund_overflow": True},
        PLATFORM_BANKING:   {"test_account_idor": True, "test_consent_overflow": True},
        PLATFORM_ECOMMERCE: {"test_price_manipulation": True, "test_inventory_bypass": True},
        PLATFORM_UNKNOWN:   {"test_all_generic": True},
    }.get(ptype, {})


def _default_chains(ptype: str) -> list[str]:
    return {
        PLATFORM_STREAMING: ["CHAIN_STREAMING_1"],
        PLATFORM_FINTECH:   ["CHAIN_FINTECH_1", "CHAIN_FINTECH_2"],
        PLATFORM_BANKING:   ["CHAIN_BANKING_1"],
        PLATFORM_ECOMMERCE: ["CHAIN_ECOMMERCE_1"],
        PLATFORM_UNKNOWN:   ["CHAIN_1", "CHAIN_6", "CHAIN_7"],
    }.get(ptype, [])
