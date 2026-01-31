# Email setup – farmityforyou@gmail.com

Your app is set to send OTP and other emails **from** `farmityforyou@gmail.com`. You only need to add the **App Password** (Gmail does not use your normal password for apps).

## How to get the email host password (Gmail App Password)

Gmail does not use your normal account password for SMTP. You must create a **Gmail App Password** (a 16-character code). Steps:

### 1. Turn on 2-Step Verification (required for App Passwords)

1. Go to [Google Account](https://myaccount.google.com/)
2. Sign in with **farmityforyou@gmail.com**
3. Click **Security** (left menu)
4. Under “How you sign in to Google”, click **2-Step Verification**
5. If it’s off, turn it **On** and complete the setup (phone or authenticator)

### 2. Create an App Password

1. Still in [Google Account → Security](https://myaccount.google.com/security)
2. Under “How you sign in to Google”, click **App passwords**
   - If you don’t see it, make sure 2-Step Verification is **On**
3. At the bottom, select app: **Mail**, device: **Other** and type **Farmity**
4. Click **Generate**
5. Google shows a **16-character password** (like `abcd efgh ijkl mnop`)
6. **Copy it** (no spaces when you use it)

### 3. Add it to your project

1. In your project folder, create a file named **`.env`** (or open it if it exists)
2. Add this line (paste your 16-character app password, no spaces):

   ```
   EMAIL_HOST_PASSWORD=abcdefghijklmnop
   ```

   Example if Google gave you `abcd efgh ijkl mnop`:

   ```
   EMAIL_HOST_PASSWORD=abcdefghijklmnop
   ```

3. Save the file
4. Restart Django: stop the server (Ctrl+C) and run `python manage.py runserver` again

### Summary

| Setting            | Value                      | Where it’s set        |
|--------------------|----------------------------|------------------------|
| Email host (sender)| farmityforyou@gmail.com    | Already in settings.py |
| Host / server      | smtp.gmail.com             | Already in settings.py |
| **Password**       | 16-char Gmail App Password | You put it in `.env`   |

After this, OTP and other emails will be sent from **farmityforyou@gmail.com** to your users’ inboxes.

---

## "Username and Password not accepted" (535 BadCredentials)

If you see this when sending email:

1. **Do not use your normal Gmail password.** Gmail blocks app logins with your regular password. You must use a **Gmail App Password** (see steps above).

2. **Enable 2-Step Verification** on farmityforyou@gmail.com first. App Passwords are only available when 2-Step Verification is on.  
   [Google Account → Security → 2-Step Verification](https://myaccount.google.com/signinoptions/two-step-verification)

3. **Create a new App Password** for farmityforyou@gmail.com:  
   [Google App Passwords](https://myaccount.google.com/apppasswords)  
   - Sign in with **farmityforyou@gmail.com**  
   - App: **Mail**, Device: **Other (Farmity)** → **Generate**  
   - Copy the 16-character code

4. **Put it in `.env` with no spaces.**  
   If Google shows `abcd efgh ijkl mnop`, use:
   ```
   EMAIL_HOST_PASSWORD=abcdefghijklmnop
   ```
   No spaces, no quotes (unless the password contains a space, which it shouldn’t).

5. Save `.env`, then run again:  
   `python manage.py test_email your@gmail.com`
