# Farmity Customer Support – Guide

Support is built into the app as a **floating widget** (no separate support page). **Admin only** handles support by default; admins can also add more support staff via Django Admin.

---

## 1. How It Works

- **Floating support button**: Fixed at the **bottom-right corner** on dashboards and chat pages. Click it to open the support panel (no navigation to another page).
- **Support panel** (slides in from the right):
  - **FAQ** – Default questions and answers; click to expand/collapse.
  - **My tickets** – List of your support requests; click one to open the conversation.
  - **New request** – Form to create a ticket (subject + message).
  - **Open (Admin)** – Only visible to **admin** (and any added support staff). Lists open tickets to handle.
- **Ticket conversation**: In the same panel you can read messages and reply. Admins can **Assign to me**, change **status** (Open → In progress → Answered → Closed), and reply.
- **Support staff**: By default only **admin** can handle tickets. You can add more staff in Django Admin → **Support staff profiles** (optional).

---

## 2. For Users (Farmers, Buyers, Vendors, Experts)

### Where to find support

- On **any dashboard** (User, Farmer, Vendor, Expert) and on **Chat** pages: look for the **green headset icon** at the **bottom-right** of the screen.
- Click it to open the support panel. Everything happens in that panel (no new page).

### In the panel

1. **FAQ** – Click a question to see the answer.
2. **My tickets** – See your tickets; click to open the thread and reply.
3. **New request** – Enter subject and message, then **Submit**. You’re taken into that ticket’s conversation.

---

## 3. For Admin (Handling Support)

- Open any dashboard (e.g. Admin Dashboard). Use the same **bottom-right support button**.
- In the panel you’ll see the **Open (Admin)** tab. There you can:
  - See open/in-progress tickets from all users.
  - Click a ticket to open the conversation.
  - **Assign to me** – Assign the ticket to yourself and set status to In progress.
  - **Status** dropdown – Set Open, In progress, Answered, or Closed.
  - **Reply** – Type and send; the user will see it in their “My tickets” view.

No separate support UI: everything is in the floating panel.

---

## 4. Adding More Support Staff (Optional)

- Go to **Django Admin** → **Accounts** → **Support staff profiles**.
- Add a **Support staff profile** for a user (same user can be admin or a separate “support” account).
- That user will then see the **Open (Admin)** tab and can handle tickets like admin.
- For now, if you don’t add anyone, **admin only** handles support.

---

## 5. Default Questions (FAQ)

Default FAQs are created by migration. You can edit them in **Django Admin** → **Accounts** → **FAQs**:

| Category     | Example question |
|------------|-------------------|
| Account    | How do I reset my password? |
| Account    | How can I verify my account (KYC)? |
| Orders     | How do I place an order? / How do I track my order? |
| Appointments | How do I book an appointment with an expert? |
| Chat       | How do I chat with an agricultural expert? |
| Support    | Who can I contact for direct support? |

---

## 6. Summary

- **Support** = bottom-right floating button → slide-out panel (no separate page).
- **Admin only** handles support by default; optional extra staff via **Support staff profiles** in Django Admin.
- Users: FAQ, My tickets, New request. Admins: same + **Open (Admin)** to handle and reply to tickets.
