import pandas as pd

validation_data = [

    # =========================
    # LEGITIMATE EMAILS - 0
    # =========================

    {
        "text": """Subject: Your Amazon order has shipped

Hello Sadaf,

Your order has been shipped and is on its way.

You can view the delivery status from your Amazon account.

Thank you,
Amazon""",
        "label": 0,
        "category": "legitimate_shopping"
    },

    {
        "text": """Subject: Microsoft account password changed

Your Microsoft account password was successfully changed.

If you made this change, no further action is required.

Microsoft Account Team""",
        "label": 0,
        "category": "legitimate_security"
    },

    {
        "text": """Subject: Your bank statement is ready

Dear Customer,

Your monthly account statement is now available in your online banking account.

You can sign in through your usual banking application to view it.

Thank you,
Customer Service""",
        "label": 0,
        "category": "legitimate_banking"
    },

    {
        "text": """Subject: Google security alert

A new sign-in was detected on your Google Account.

Device: Windows
Location: India

If this was you, you can safely ignore this message.

Google Account Security""",
        "label": 0,
        "category": "legitimate_security"
    },

    {
        "text": """Subject: Your Flipkart order is out for delivery

Your order is out for delivery today.

You can check the current delivery status from the Flipkart app.

Thank you for shopping with us.""",
        "label": 0,
        "category": "legitimate_delivery"
    },

    {
        "text": """Subject: Meeting scheduled for tomorrow

Hi Team,

The project meeting has been scheduled for tomorrow at 11:00 AM.

Please review the attached agenda before the meeting.

Regards,
Project Team""",
        "label": 0,
        "category": "legitimate_workplace"
    },

    {
        "text": """Subject: GitHub notification

A new comment was added to your pull request.

You can review the discussion from your GitHub repository.

GitHub""",
        "label": 0,
        "category": "legitimate_workplace"
    },

    {
        "text": """Subject: Your password reset request

We received a request to reset your account password.

If you requested this change, continue through the password reset process.

If you did not request it, you can ignore this email.

Support Team""",
        "label": 0,
        "category": "legitimate_password"
    },

    {
        "text": """Subject: College examination schedule

Dear Students,

The examination schedule for the upcoming semester has been published.

Please check the official college portal for the complete timetable.

Academic Office""",
        "label": 0,
        "category": "legitimate_education"
    },

    {
        "text": """Subject: Payment received

Hello,

We have successfully received your payment.

Your transaction has been completed and the receipt is available in your account.

Thank you.""",
        "label": 0,
        "category": "legitimate_payment"
    },

    {
        "text": """Subject: LinkedIn notification

You have a new connection request on LinkedIn.

Open the LinkedIn application to view the request.

LinkedIn""",
        "label": 0,
        "category": "legitimate_social"
    },

    {
        "text": """Subject: Delivery confirmation

Your package was delivered successfully today.

Thank you for using our delivery service.""",
        "label": 0,
        "category": "legitimate_delivery"
    },

    {
        "text": """Subject: Team project update

Hi everyone,

The latest version of the project documentation has been uploaded.

Please review the changes before Friday.

Regards,
Development Team""",
        "label": 0,
        "category": "legitimate_workplace"
    },

    {
        "text": """Subject: Subscription renewal confirmation

Your subscription has been renewed successfully.

Your next billing date is shown in your account settings.

Thank you.""",
        "label": 0,
        "category": "legitimate_subscription"
    },

    {
        "text": """Subject: Welcome to your new account

Welcome!

Your account has been successfully created.

You can sign in through the official application whenever you are ready.

Thank you.""",
        "label": 0,
        "category": "legitimate_account"
    },


    # =========================
    # PHISHING EMAILS - 1
    # =========================

    {
        "text": """Subject: URGENT - Amazon account suspended

Your Amazon account has been permanently suspended.

Verify your password and payment information immediately using the secure link below.

Failure to verify within 30 minutes will result in permanent account closure.""",
        "label": 1,
        "category": "phishing_account"
    },

    {
        "text": """Subject: Microsoft security verification required

Your Microsoft account has been compromised.

Confirm your password, recovery code and two-factor authentication code immediately to prevent account termination.

Click the verification link now.""",
        "label": 1,
        "category": "phishing_credential"
    },

    {
        "text": """Subject: Bank account verification

Your bank account has been flagged for suspicious activity.

To prevent your account from being blocked, verify your account number, password, card number and OTP immediately.

Failure to respond will result in suspension.""",
        "label": 1,
        "category": "phishing_banking"
    },

    {
        "text": """Subject: Refund verification required

You are eligible for a refund of ₹25,000.

To receive your refund, confirm your card number, CVV and OTP using the secure verification page.

This offer expires today.""",
        "label": 1,
        "category": "phishing_financial"
    },

    {
        "text": """Subject: Your package cannot be delivered

Your package is currently on hold because your delivery address could not be verified.

Pay ₹49 immediately and confirm your card information to release the package.""",
        "label": 1,
        "category": "phishing_delivery"
    },

    {
        "text": """Subject: Account password expires today

Your account password will expire today.

Verify your current password and security code using the link below to prevent account termination.

Act immediately.""",
        "label": 1,
        "category": "phishing_credential"
    },

    {
        "text": """Subject: Security breach detected

We detected unauthorized activity on your account.

For security purposes, reply with your username, password and verification code so that our security team can secure your account.""",
        "label": 1,
        "category": "phishing_credential"
    },

    {
        "text": """Subject: Google account warning

Your Google account will be deleted within 24 hours.

Confirm your login credentials immediately through the attached verification page to prevent permanent deletion.""",
        "label": 1,
        "category": "phishing_account"
    },

    {
        "text": """Subject: Payment failed - immediate action required

Your recent payment could not be processed.

To avoid account suspension, click the link below and enter your card details and OTP again.""",
        "label": 1,
        "category": "phishing_payment"
    },

    {
        "text": """Subject: IT Department - urgent verification

This is an urgent security request from the IT department.

Send your corporate username, password and authentication code immediately so we can verify your identity.""",
        "label": 1,
        "category": "phishing_social_engineering"
    },

    {
        "text": """Subject: Congratulations! You have won ₹10 lakh

You have been selected as the winner of our cash prize.

To claim your prize, provide your bank account number and card details immediately.

Your prize will expire today.""",
        "label": 1,
        "category": "phishing_prize"
    },

    {
        "text": """Subject: Your Netflix account requires verification

Your Netflix membership has been suspended because your billing information could not be verified.

Click the secure link and enter your card details to restore your subscription.""",
        "label": 1,
        "category": "phishing_payment"
    },

    {
        "text": """Subject: Office account security warning

We detected suspicious activity on your company account.

Click the attached link and enter your company email password to confirm your identity.

Failure to comply will result in account termination.""",
        "label": 1,
        "category": "phishing_workplace"
    },

    {
        "text": """Subject: Urgent invoice payment

The attached invoice is overdue.

Complete the payment immediately using the payment link below to avoid legal action and additional charges.""",
        "label": 1,
        "category": "phishing_financial"
    },

    {
        "text": """Subject: Verify your PayPal account

Your PayPal account has been limited.

To restore access, confirm your email password, card number and security code through the verification page immediately.""",
        "label": 1,
        "category": "phishing_credential"
    }
]

df = pd.DataFrame(validation_data)

output_path = "dataset/validation_emails.csv"
df.to_csv(output_path, index=False)

print("Validation dataset created successfully!")
print("File:", output_path)
print("Total emails:", len(df))
print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nCategory distribution:")
print(df["category"].value_counts())