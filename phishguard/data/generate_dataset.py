"""
generate_dataset.py
--------------------
Builds a labeled dataset of phishing vs. legitimate email texts.

Why synthetic data?
In a real deployment you'd train on a large public dataset (e.g. the
Kaggle "Phishing Email Detection" dataset, or the SpamAssassin public
corpus). Those need an internet download from your own machine.
This script generates realistic examples covering the same attack
patterns named in the SIH problem statement (urgency cues, credential
harvesting, fake invoices, executive impersonation, prize scams) so
the model works out of the box. Swap in a real dataset later for a
stronger model -- instructions are in README.md.
"""

import random
import csv

random.seed(42)

# ---- PHISHING TEMPLATES ----
# Grouped by the attack pattern types mentioned in the problem statement
phishing_templates = [
    # Credential harvesting
    "Your {service} account has been suspended. Click here to verify your identity immediately: {link}",
    "Unusual sign-in activity detected on your {service} account. Confirm your password now at {link} or your account will be locked.",
    "Security Alert: We noticed a login from a new device. Verify it's you: {link}",
    "Your {service} password expires today. Update it now to avoid losing access: {link}",
    "Action required: Your mailbox storage is full. Click {link} to upgrade and avoid message loss.",

    # Prize / lottery scams
    "Congratulations! You have won a {prize} prize. Claim your reward within 24 hours: {link}",
    "You are our lucky winner of this month's {service} giveaway. Click {link} to claim {prize} now.",
    "Final notice: your {prize} reward will expire soon. Confirm your details at {link}.",

    # Business Email Compromise / fake invoice
    "Hi, please process the attached invoice for {amount} urgently. Payment details have changed, see updated bank info attached.",
    "This is urgent. I need you to process a wire transfer of {amount} today before the bank closes. Reply for account details.",
    "Kindly update the vendor payment account to the new details before releasing this week's payment of {amount}.",
    "Please find attached the revised invoice. Kindly process payment of {amount} to the new account before end of day.",

    # Executive impersonation
    "Hi, this is {exec_name}, I'm in a meeting and need you to purchase gift cards worth {amount} urgently. Reply ASAP, can't talk right now.",
    "I need this handled quietly and quickly - transfer {amount} to the account I'll send shortly. Do not discuss with anyone in the office. - {exec_name}",
    "From the desk of {exec_name}: I'm travelling and my usual assistant is unavailable. Please action this payment of {amount} immediately.",

    # Urgency / social engineering
    "URGENT: Your account will be permanently deleted in 24 hours unless you verify your details now: {link}",
    "Immediate action required. Failure to respond within 12 hours will result in account suspension. Click {link}",
    "Warning: suspicious activity detected. Verify your identity within 1 hour to prevent permanent account closure: {link}",
    "Your payment could not be processed. Update your billing information immediately at {link} to avoid service interruption.",

    # Malicious link / attachment
    "Please review the attached document and sign it using the secure portal here: {link}",
    "Your package could not be delivered. Click {link} to reschedule delivery and pay a small customs fee.",
    "A voicemail message is waiting for you. Listen now: {link}",
]

phishing_fillers = {
    "service": ["Microsoft 365", "Google Workspace", "PayPal", "Netflix", "Bank Secure Portal", "Amazon", "Apple ID", "your company email"],
    "link": ["http://secure-verify-login.com/reset", "http://accounts-update-portal.net/login",
             "http://bit.ly/3xVerify", "http://paypal-security-check.info", "http://192.168.44.12/login.php",
             "http://amaz0n-support.com/verify", "http://microsft-office365-login.com"],
    "prize": ["$1,000,000", "a brand new iPhone 16", "a $500 gift card", "a free vacation package"],
    "amount": ["$45,000", "$12,750", "$8,900", "$120,000", "$3,400"],
    "exec_name": ["John (CEO)", "the Managing Director", "your Finance Head", "David (CFO)"],
}

# ---- LEGITIMATE TEMPLATES ----
legit_templates = [
    "Hi team, please find attached the agenda for tomorrow's {meeting_type} meeting at {time}.",
    "Reminder: the quarterly report is due by {day}. Let me know if you need an extension.",
    "Thanks for your email. I'll review the document and get back to you by {day}.",
    "Hi, could you please share the updated {doc_type} when you get a chance? No rush.",
    "Attached is the minutes of today's {meeting_type} meeting for your reference.",
    "Hello, just confirming our call is scheduled for {time} on {day}. Let me know if that still works.",
    "Please find the monthly newsletter attached. Feedback is welcome as always.",
    "Hi, following up on our conversation last week regarding the {doc_type}. Any updates?",
    "Your order #{order_id} has shipped and is expected to arrive by {day}.",
    "Thank you for registering for our webinar on {meeting_type}. Here are the joining details for {time}.",
    "Hi, the {doc_type} you requested is attached. Let me know if you need anything else.",
    "This is a reminder that your subscription renews on {day}. No action is needed if you wish to continue.",
    "Hi everyone, welcome to the team! Looking forward to working with you all.",
    "Please review the attached {doc_type} and share your comments by end of week.",
    "Hi, can we reschedule our {meeting_type} meeting to {time} on {day}? Let me know if that works for you.",
    "Your recent payment for order #{order_id} was successful. Thank you for your purchase.",
    "Hi, sharing the notes from our {meeting_type} discussion. Please add anything I missed.",
    "Congratulations on completing the training program! Your certificate is attached.",
]

legit_fillers = {
    "meeting_type": ["project status", "budget review", "team sync", "onboarding", "client review"],
    "time": ["10:00 AM", "2:30 PM", "11:15 AM", "4:00 PM"],
    "day": ["Friday", "next Monday", "the 15th", "end of this week"],
    "doc_type": ["proposal", "budget sheet", "presentation", "report", "contract draft"],
    "order_id": ["58291", "77420", "10234", "99581"],
}


def fill_template(template, fillers):
    text = template
    for key, options in fillers.items():
        if "{" + key + "}" in text:
            text = text.replace("{" + key + "}", random.choice(options))
    return text


def generate_rows(templates, fillers, label, n_per_template=8):
    rows = []
    for t in templates:
        for _ in range(n_per_template):
            rows.append({"text": fill_template(t, fillers), "label": label})
    return rows


def main():
    rows = []
    rows += generate_rows(phishing_templates, phishing_fillers, "phishing", n_per_template=10)
    rows += generate_rows(legit_templates, legit_fillers, "legitimate", n_per_template=10)

    random.shuffle(rows)

    import os
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emails_dataset.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} rows -> {out_path}")
    phishing_count = sum(1 for r in rows if r["label"] == "phishing")
    legit_count = sum(1 for r in rows if r["label"] == "legitimate")
    print(f"Phishing: {phishing_count}, Legitimate: {legit_count}")


if __name__ == "__main__":
    main()
