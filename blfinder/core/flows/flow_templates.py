"""
BLFinder v3.0 — core/flows/flow_templates.py
Pre-built Business Flow Templates

Ready-to-use multi-step flow definitions for common application types.
Each template uses {{variable}} placeholders for dynamic values extracted
from earlier steps.

Templates included:
  - E-commerce checkout (add to cart → coupon → checkout → payment)
  - User registration + email verification
  - Password reset flow
  - Subscription upgrade
  - Funds transfer / withdrawal
  - API key creation
  - KYC / identity verification
  - Appointment booking

Usage:
    steps = FlowTemplates.ecommerce_checkout(
        product_id=123,
        coupon_code="SAVE10",
    )
    results = await replayer.attack(steps, base_url="https://api.target.com")
"""

from __future__ import annotations
from .flow_replayer import FlowStep


class FlowTemplates:
    """
    Factory class for pre-built business flow templates.
    All methods return list[FlowStep] ready for FlowReplayer.
    """

    # ── E-Commerce Flows ──────────────────────────────────────────────────────

    @staticmethod
    def ecommerce_checkout(
        product_id: int = 1,
        quantity: int = 1,
        price: float = 99.99,
        coupon_code: str = "",
        shipping_address: dict | None = None,
    ) -> list[FlowStep]:
        """
        Full e-commerce checkout flow:
        1. Add item to cart
        2. Apply coupon (if provided)
        3. Set shipping address
        4. Review order
        5. Create order
        6. Process payment

        Attack points: price (steps 1, 5, 6), coupon (step 2),
                       quantity (step 1), state (step 5).
        """
        address = shipping_address or {
            "street": "123 Test St",
            "city":   "Testville",
            "zip":    "12345",
            "country": "US",
        }

        steps = [
            FlowStep(
                id="add_to_cart",
                method="POST",
                url="/api/cart/items",
                body={
                    "product_id": product_id,
                    "quantity":   quantity,
                    "price":      price,
                },
                extract={
                    "cart_id":     "$.cart.id",
                    "item_id":     "$.item.id",
                    "cart_total":  "$.cart.total",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="set_shipping",
                method="PUT",
                url="/api/cart/{{cart_id}}/shipping",
                body={
                    "cart_id": "{{cart_id}}",
                    "address": address,
                },
                extract={
                    "shipping_cost": "$.shipping.cost",
                    "delivery_date": "$.shipping.estimated_date",
                },
                expected_status=[200, 201],
                attack_here=False,
                required=False,
            ),
            FlowStep(
                id="review_order",
                method="GET",
                url="/api/cart/{{cart_id}}/review",
                extract={
                    "order_token":  "$.review_token",
                    "final_total":  "$.totals.final",
                    "tax_amount":   "$.totals.tax",
                },
                expected_status=[200],
                attack_here=False,
                required=False,
            ),
            FlowStep(
                id="create_order",
                method="POST",
                url="/api/orders",
                body={
                    "cart_id":      "{{cart_id}}",
                    "review_token": "{{order_token}}",
                    "total":        "{{final_total}}",
                },
                extract={
                    "order_id":     "$.order.id",
                    "order_status": "$.order.status",
                    "payment_ref":  "$.payment_reference",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="process_payment",
                method="POST",
                url="/api/payments",
                body={
                    "order_id":       "{{order_id}}",
                    "amount":         "{{final_total}}",
                    "currency":       "USD",
                    "payment_method": "card",
                },
                extract={
                    "payment_id":     "$.payment.id",
                    "payment_status": "$.payment.status",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
        ]

        # Inject coupon step after add_to_cart if a code was provided
        if coupon_code:
            coupon_step = FlowStep(
                id="apply_coupon",
                method="POST",
                url="/api/cart/{{cart_id}}/coupon",
                body={
                    "cart_id":    "{{cart_id}}",
                    "coupon_code": coupon_code,
                },
                extract={
                    "discount_amount": "$.discount.amount",
                    "discounted_total": "$.cart.total",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=False,
            )
            steps.insert(1, coupon_step)

        return steps

    @staticmethod
    def ecommerce_refund(
        order_id: int = 1,
        item_id: int = 1,
        amount: float = 99.99,
    ) -> list[FlowStep]:
        """
        Refund/return request flow.
        Attack: manipulate refund amount > original, negative amount, duplicate refund.
        """
        return [
            FlowStep(
                id="initiate_return",
                method="POST",
                url="/api/orders/{{order_id}}/returns",
                body={
                    "order_id": order_id,
                    "item_id":  item_id,
                    "reason":   "defective",
                },
                extract={
                    "return_id":    "$.return.id",
                    "return_token": "$.return.token",
                },
                expected_status=[200, 201],
                attack_here=False,
                required=True,
            ),
            FlowStep(
                id="confirm_refund",
                method="POST",
                url="/api/refunds",
                body={
                    "return_id":    "{{return_id}}",
                    "return_token": "{{return_token}}",
                    "amount":       amount,
                    "order_id":     order_id,
                },
                extract={
                    "refund_id":     "$.refund.id",
                    "refund_status": "$.refund.status",
                    "refund_amount": "$.refund.amount",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
        ]

    @staticmethod
    def subscription_upgrade(
        current_plan: str = "free",
        target_plan: str = "premium",
        plan_price: float = 29.99,
    ) -> list[FlowStep]:
        """
        Subscription upgrade flow.
        Attack: force plan without payment, price manipulation, direct state change.
        """
        return [
            FlowStep(
                id="select_plan",
                method="POST",
                url="/api/subscriptions/select",
                body={
                    "plan":  target_plan,
                    "price": plan_price,
                },
                extract={
                    "upgrade_token": "$.upgrade_token",
                    "plan_id":       "$.plan.id",
                    "billing_cycle": "$.plan.billing_cycle",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="confirm_upgrade",
                method="POST",
                url="/api/subscriptions/upgrade",
                body={
                    "upgrade_token": "{{upgrade_token}}",
                    "plan_id":       "{{plan_id}}",
                    "amount":        plan_price,
                    "plan":          target_plan,
                },
                extract={
                    "subscription_id":     "$.subscription.id",
                    "subscription_status": "$.subscription.status",
                    "new_plan":            "$.subscription.plan",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="verify_upgrade",
                method="GET",
                url="/api/subscriptions/{{subscription_id}}",
                extract={
                    "active_plan": "$.subscription.plan",
                    "is_premium":  "$.subscription.is_premium",
                },
                expected_status=[200],
                attack_here=False,
                required=False,
            ),
        ]

    # ── Financial Flows ───────────────────────────────────────────────────────

    @staticmethod
    def funds_transfer(
        sender_account: str = "",
        recipient_account: str = "",
        amount: float = 100.0,
        currency: str = "USD",
    ) -> list[FlowStep]:
        """
        Bank/wallet funds transfer flow.
        Attack: negative transfer (receive funds), zero amount, race condition on deduction.
        """
        return [
            FlowStep(
                id="initiate_transfer",
                method="POST",
                url="/api/transfers/initiate",
                body={
                    "from_account": sender_account or "{{account_id}}",
                    "to_account":   recipient_account,
                    "amount":       amount,
                    "currency":     currency,
                },
                extract={
                    "transfer_id":    "$.transfer.id",
                    "transfer_token": "$.transfer.token",
                    "fee":            "$.transfer.fee",
                    "total_debit":    "$.transfer.total_debit",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="confirm_transfer",
                method="POST",
                url="/api/transfers/{{transfer_id}}/confirm",
                body={
                    "transfer_id":    "{{transfer_id}}",
                    "transfer_token": "{{transfer_token}}",
                    "amount":         amount,
                },
                extract={
                    "confirmation_id": "$.confirmation.id",
                    "new_balance":     "$.account.balance",
                    "status":          "$.transfer.status",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
        ]

    @staticmethod
    def withdrawal(
        account_id: str = "",
        amount: float = 50.0,
        destination: str = "",
    ) -> list[FlowStep]:
        """
        Withdrawal / cash-out flow.
        Attack: negative amount (deposit instead), race condition, bypass 2FA.
        """
        return [
            FlowStep(
                id="request_withdrawal",
                method="POST",
                url="/api/withdrawals",
                body={
                    "account_id":  account_id or "{{account_id}}",
                    "amount":      amount,
                    "destination": destination,
                },
                extract={
                    "withdrawal_id":    "$.withdrawal.id",
                    "otp_required":     "$.withdrawal.otp_required",
                    "withdrawal_token": "$.withdrawal.token",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="verify_otp",
                method="POST",
                url="/api/withdrawals/{{withdrawal_id}}/verify",
                body={
                    "withdrawal_id": "{{withdrawal_id}}",
                    "otp":           "123456",
                },
                extract={
                    "verified": "$.verified",
                },
                expected_status=[200, 201],
                attack_here=False,
                required=False,
            ),
            FlowStep(
                id="execute_withdrawal",
                method="POST",
                url="/api/withdrawals/{{withdrawal_id}}/execute",
                body={
                    "withdrawal_id":    "{{withdrawal_id}}",
                    "withdrawal_token": "{{withdrawal_token}}",
                    "amount":           amount,
                },
                extract={
                    "status":      "$.withdrawal.status",
                    "new_balance": "$.account.balance",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
        ]

    # ── Auth Flows ────────────────────────────────────────────────────────────

    @staticmethod
    def password_reset(
        email: str = "victim@example.com",
    ) -> list[FlowStep]:
        """
        Password reset flow.
        Attack: reset token reuse, bypass OTP, account takeover via token manipulation.
        """
        return [
            FlowStep(
                id="request_reset",
                method="POST",
                url="/api/auth/password/reset",
                body={"email": email},
                extract={
                    "reset_token": "$.reset_token",
                    "user_id":     "$.user_id",
                },
                expected_status=[200, 201],
                attack_here=False,
                required=True,
            ),
            FlowStep(
                id="verify_reset_token",
                method="POST",
                url="/api/auth/password/verify",
                body={
                    "token":   "{{reset_token}}",
                    "user_id": "{{user_id}}",
                },
                extract={"session_token": "$.session_token"},
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="set_new_password",
                method="POST",
                url="/api/auth/password/change",
                body={
                    "session_token":     "{{session_token}}",
                    "new_password":      "NewP@ssw0rd!",
                    "confirm_password":  "NewP@ssw0rd!",
                },
                extract={"changed": "$.success"},
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
        ]

    @staticmethod
    def user_registration(
        email: str = "newuser@test.com",
        password: str = "TestPass123!",
        role: str = "user",
    ) -> list[FlowStep]:
        """
        User registration + email verification flow.
        Attack: mass assignment during registration, skip email verification,
                force role escalation.
        """
        return [
            FlowStep(
                id="register",
                method="POST",
                url="/api/auth/register",
                body={
                    "email":    email,
                    "password": password,
                    "role":     role,
                },
                extract={
                    "user_id":          "$.user.id",
                    "verification_token": "$.verification_token",
                },
                expected_status=[200, 201],
                attack_here=True,     # Mass assignment attack here
                required=True,
            ),
            FlowStep(
                id="verify_email",
                method="POST",
                url="/api/auth/verify-email",
                body={
                    "user_id": "{{user_id}}",
                    "token":   "{{verification_token}}",
                },
                extract={
                    "is_verified": "$.user.email_verified",
                    "auth_token":  "$.token",
                },
                expected_status=[200, 201],
                attack_here=True,     # Workflow bypass — skip this step
                required=False,
            ),
            FlowStep(
                id="complete_profile",
                method="POST",
                url="/api/users/{{user_id}}/profile",
                body={
                    "user_id": "{{user_id}}",
                    "name":    "Test User",
                },
                extract={"profile_complete": "$.profile.complete"},
                expected_status=[200, 201],
                attack_here=True,
                required=False,
            ),
        ]

    # ── Reward / Loyalty Flows ────────────────────────────────────────────────

    @staticmethod
    def redeem_reward(
        reward_id: str = "REWARD_001",
        user_id: str = "",
    ) -> list[FlowStep]:
        """
        Loyalty reward redemption flow.
        Attack: race condition (redeem same reward multiple times),
                replay already-used reward token.
        """
        return [
            FlowStep(
                id="check_reward",
                method="GET",
                url="/api/rewards/{{reward_id}}",
                params={"reward_id": reward_id},
                extract={
                    "reward_value": "$.reward.value",
                    "is_redeemable": "$.reward.is_redeemable",
                },
                expected_status=[200],
                attack_here=False,
                required=True,
            ),
            FlowStep(
                id="redeem_reward",
                method="POST",
                url="/api/rewards/redeem",
                body={
                    "reward_id": reward_id,
                    "user_id":   user_id or "{{user_id}}",
                },
                extract={
                    "redemption_id": "$.redemption.id",
                    "credit_added":  "$.account.credit_added",
                    "new_balance":   "$.account.balance",
                },
                expected_status=[200, 201],
                attack_here=True,     # Race condition target
                required=True,
            ),
        ]

    @staticmethod
    def referral_bonus(
        referral_code: str = "REF123",
        referrer_id: str = "",
    ) -> list[FlowStep]:
        """
        Referral bonus claim flow.
        Attack: self-referral, race condition on bonus, replay used referral codes.
        """
        return [
            FlowStep(
                id="apply_referral",
                method="POST",
                url="/api/referrals/apply",
                body={
                    "referral_code": referral_code,
                    "referrer_id":   referrer_id,
                },
                extract={
                    "referral_id":    "$.referral.id",
                    "bonus_amount":   "$.referral.bonus",
                    "referral_token": "$.referral.token",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
            FlowStep(
                id="claim_bonus",
                method="POST",
                url="/api/referrals/{{referral_id}}/claim",
                body={
                    "referral_id":    "{{referral_id}}",
                    "referral_token": "{{referral_token}}",
                    "amount":         "{{bonus_amount}}",
                },
                extract={
                    "claimed":       "$.success",
                    "credit_added":  "$.account.credit_added",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
        ]

    # ── Admin / KYC Flows ─────────────────────────────────────────────────────

    @staticmethod
    def kyc_verification(
        user_id: str = "",
        document_type: str = "passport",
    ) -> list[FlowStep]:
        """
        KYC identity verification flow.
        Attack: skip document upload, force verification_status=verified,
                mass assignment on kyc_level.
        """
        return [
            FlowStep(
                id="submit_kyc",
                method="POST",
                url="/api/kyc/submit",
                body={
                    "user_id":       user_id or "{{user_id}}",
                    "document_type": document_type,
                    "status":        "pending",
                },
                extract={
                    "kyc_id":    "$.kyc.id",
                    "kyc_token": "$.kyc.token",
                },
                expected_status=[200, 201],
                attack_here=True,     # Force status = verified
                required=True,
            ),
            FlowStep(
                id="upload_document",
                method="POST",
                url="/api/kyc/{{kyc_id}}/documents",
                body={
                    "kyc_id":    "{{kyc_id}}",
                    "doc_type":  document_type,
                    "doc_data":  "base64_placeholder",
                },
                extract={"doc_id": "$.document.id"},
                expected_status=[200, 201],
                attack_here=False,
                required=False,       # Skip this to test workflow bypass
            ),
            FlowStep(
                id="verify_kyc",
                method="PUT",
                url="/api/kyc/{{kyc_id}}/status",
                body={
                    "kyc_id":              "{{kyc_id}}",
                    "kyc_token":           "{{kyc_token}}",
                    "verification_status": "verified",
                    "kyc_level":           3,
                },
                extract={
                    "verification_status": "$.kyc.status",
                    "kyc_level":           "$.kyc.level",
                },
                expected_status=[200, 201],
                attack_here=True,     # Force verification
                required=True,
            ),
        ]

    @staticmethod
    def api_key_creation(
        key_name: str = "test_key",
        permissions: list | None = None,
    ) -> list[FlowStep]:
        """
        API key creation flow.
        Attack: mass assignment of permissions, skip verification step,
                create keys with admin scope.
        """
        return [
            FlowStep(
                id="request_api_key",
                method="POST",
                url="/api/keys",
                body={
                    "name":        key_name,
                    "permissions": permissions or ["read"],
                    "scope":       "standard",
                },
                extract={
                    "key_id":           "$.key.id",
                    "verification_url": "$.verification_url",
                    "key_token":        "$.key.token",
                },
                expected_status=[200, 201],
                attack_here=True,     # Mass assignment: add admin permissions
                required=True,
            ),
            FlowStep(
                id="activate_key",
                method="POST",
                url="/api/keys/{{key_id}}/activate",
                body={
                    "key_id":    "{{key_id}}",
                    "key_token": "{{key_token}}",
                },
                extract={
                    "api_key":    "$.key.value",
                    "key_status": "$.key.status",
                },
                expected_status=[200, 201],
                attack_here=True,
                required=True,
            ),
        ]

    # ── Generic Builder ───────────────────────────────────────────────────────

    @staticmethod
    def from_json(flow_def: dict) -> list[FlowStep]:
        """
        Build a flow from a JSON definition dict (as loaded from flows.json).

        Expected format:
        {
          "name": "my_flow",
          "steps": [
            {
              "id": "step1",
              "method": "POST",
              "url": "/api/endpoint",
              "body": {"field": "value"},
              "extract": {"var": "$.path"},
              "attack_here": true,
              "required": true
            }
          ]
        }
        """
        steps = []
        for step_def in flow_def.get("steps", []):
            step = FlowStep(
                id=step_def.get("id", f"step_{len(steps)}"),
                method=step_def.get("method", "GET").upper(),
                url=step_def.get("url", ""),
                body=step_def.get("body", {}),
                params=step_def.get("params", {}),
                headers=step_def.get("headers", {}),
                extract=step_def.get("extract", {}),
                attack_here=step_def.get("attack_here", False),
                skip=step_def.get("skip", False),
                expected_status=step_def.get("expected_status", [200, 201]),
                delay=step_def.get("delay", 0.0),
                required=step_def.get("required", True),
            )
            steps.append(step)
        return steps

    @staticmethod
    def list_all() -> list[str]:
        """Return names of all available templates."""
        return [
            "ecommerce_checkout",
            "ecommerce_refund",
            "subscription_upgrade",
            "funds_transfer",
            "withdrawal",
            "password_reset",
            "user_registration",
            "redeem_reward",
            "referral_bonus",
            "kyc_verification",
            "api_key_creation",
        ]
