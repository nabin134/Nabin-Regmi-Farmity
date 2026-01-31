# Fix: "Username and Password not accepted" (535 BadCredentials)

Your app is correctly configured; Gmail is rejecting the **password** you’re using. Follow these steps in order.

---

## Step 1: Use farmityforyou@gmail.com

- You must be signed in as **farmityforyou@gmail.com** (the same address in your app).
- Open: **https://myaccount.google.com/**
- If you’re on another account, sign out and sign in with **farmityforyou@gmail.com**.

---

## Step 2: Turn on 2-Step Verification (required)

1. Go to: **https://myaccount.google.com/security**
2. Find **“How you sign in to Google”**.
3. Click **“2-Step Verification”**.
4. If it says **Off**, click **Get started** and complete the setup (phone number or authenticator app).
5. When it says **On**, continue to Step 3.

Without 2-Step Verification, Google will not show the “App passwords” option.

---

## Step 3: Create an App Password (not your normal password)

1. Go to: **https://myaccount.google.com/apppasswords**
   - If you don’t see “App passwords”, 2-Step Verification is not on. Go back to Step 2.
2. You may need to sign in again with **farmityforyou@gmail.com**.
3. In “Select app”, choose **Mail**.
4. In “Select device”, choose **Other (Custom name)** and type: **Farmity**.
5. Click **Generate**.
6. Google shows a **16-character password** (e.g. `abcd efgh ijkl mnop`).
7. **Copy it** (you won’t see it again). When you paste into `.env`, **remove all spaces** (e.g. use `abcdefghijklmnop`).

---

## Step 4: Put only the App Password in `.env`

1. Open your project folder (same folder as **manage.py**).
2. Open the file **`.env`** (create it if it doesn’t exist).
3. Have **only one line** for the password (no spaces around `=`, no quotes):

   ```bash
   EMAIL_HOST_PASSWORD=abcdefghijklmnop
   ```

   Replace `abcdefghijklmnop` with your **16-character App Password with no spaces**.

   **Wrong:**
   - `EMAIL_HOST_PASSWORD=abcd efgh ijkl mnop`  (has spaces)
   - `EMAIL_HOST_PASSWORD = mypassword`          (spaces around `=`)
   - Using your normal Gmail password

   **Right:**
   - `EMAIL_HOST_PASSWORD=abcdefghijklmnop`     (16 letters, no spaces)

4. Save the file (Ctrl+S).
5. Make sure there is **no new line or extra space** after the password. The line should end right after the last letter.

---

## Step 5: Test again

In the same folder as **manage.py**, run:

```bash
python manage.py test_email your@gmail.com
```

Replace `your@gmail.com` with an address where you can check the inbox.

- If you see **“Test email sent to ...”**, the 535 error is fixed. Check that inbox (and spam).
- If you still see **535 BadCredentials**:
  - Confirm you’re signed in as **farmityforyou@gmail.com** at https://myaccount.google.com/
  - Create a **new** App Password (Step 3) and put the new 16-character code in `.env` (no spaces).
  - Do not use your normal Gmail password anywhere in `.env`.

---

## Checklist

- [ ] Signed in at Google with **farmityforyou@gmail.com**
- [ ] **2-Step Verification** is **On** for that account
- [ ] Created an **App Password** (Mail, Other “Farmity”) for **farmityforyou@gmail.com**
- [ ] In `.env`: one line `EMAIL_HOST_PASSWORD=xxxx` with the 16-character App Password **and no spaces**
- [ ] Saved `.env` and ran `python manage.py test_email your@gmail.com`

After this, OTP and other emails will send from **farmityforyou@gmail.com** to your users’ inboxes.
