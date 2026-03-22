# Email setup (Gmail / Farmity OTP & password reset)

If you see **`SMTPAuthenticationError: (535, ... Username and Password not accepted)`**, Gmail is rejecting the credentials. **You cannot use your normal Gmail password** for SMTP.

## Fix: use a Gmail App Password

1. Open [Google Account → Security](https://myaccount.google.com/security).
2. Enable **2-Step Verification** if it is not already on (required for App Passwords).
3. Search for **App passwords** (or: Security → How you sign in to Google → App passwords).
4. Create an app password for **Mail** (and your device if asked).
5. Google shows a **16-character** password, often as `xxxx xxxx xxxx xxxx`.

## Put it in `.env` (project root)

Use the **same Gmail address** as `EMAIL_HOST_USER` / `DEFAULT_FROM_EMAIL` (the account that generated the App Password).

```env
EMAIL_HOST_USER=farmityforyou@gmail.com
EMAIL_HOST_PASSWORD=abcdefghijklmnop
```

- Paste the 16 letters **without spaces** (Farmity strips spaces, but one clean line is best).
- No quotes unless your tooling requires them.

Optional overrides:

```env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=true
DEFAULT_FROM_EMAIL=farmityforyou@gmail.com
```

## Render / other hosts

Add the same variables in the hosting dashboard **Environment** tab. Redeploy or restart after changing secrets.

## Still failing?

- Confirm **2-Step Verification** is on for that Google account.
- Regenerate a new App Password and update `EMAIL_HOST_PASSWORD`.
- Ensure `EMAIL_HOST_USER` is exactly the Gmail address you used to create the App Password.
- See Google’s help: [Sign in with App Passwords](https://support.google.com/accounts/answer/185833).

## Local dev without Gmail

If you omit `EMAIL_HOST_PASSWORD`, Django uses the **console** email backend and messages print in the terminal instead of sending real mail.
