# Accounts backend setup (about 10 minutes, once)

The website and the desktop app both use the same accounts: the `users_db.json` file in your
Google Drive folder. Neither of them is allowed to touch that file directly. A small free
**Google Apps Script** (`Code.gs` in this folder) runs under your Google account and is the only
thing that reads or writes it.

## 1. Create the script

1. Sign in to Google with **the account that owns the Fast Connect Drive folder**.
2. Go to https://script.google.com and click **New project**.
3. Rename it (top left) to `Fast Connect Accounts`.
4. Delete everything in the editor, paste the whole contents of `Code.gs`, and click **Save**.

## 2. Create the admin password

There is no admin password until you make one here. Nobody else ever sees it.

1. Click **Project Settings** (gear icon on the left).
2. Under **Script Properties**, click **Add script property**:
   - Property: `ADMIN_PASSWORD`
   - Value: a password of **at least 12 characters** that you don't use anywhere else
3. Add a second property: `GEMINI_API_KEY`, with a Gemini key from https://aistudio.google.com/app/apikey
4. Click **Save script properties**.

## 3. Check it and give it permission

1. Go back to the **Editor**. In the function list at the top, choose **selfTest** and click **Run**.
2. Google asks for permission to use your Drive: click **Review permissions**, pick your account,
   then **Advanced -> Go to Fast Connect Accounts**, then **Allow**. (The warning appears because
   it's your own unpublished script.)
3. The **Execution log** at the bottom should show:
   `Hash check: OK`, a timing line, `Google Drive: OK`, `Admin password: set`, `Session secret: ready`.

## 4. Deploy it as a web app

1. Click **Deploy -> New deployment**.
2. Click the gear next to **Select type** and choose **Web app**.
3. Set **Execute as: Me** and **Who has access: Anyone**.
4. Click **Deploy** and copy the **Web app URL**. It ends in `/exec`.

To check it, open that URL in your browser. You should see `{"ok":true,"service":"Fast Connect accounts"}`.

## 5. Connect the website and the app

1. Open `config.js` (in the website folder) and paste the URL:

   ```js
   const ACCOUNTS_API_URL = 'https://script.google.com/macros/s/XXXXXXXX/exec';
   ```

2. Rebuild the downloads, because the app carries the same URL inside it, then refresh the
   `github` folder:

   ```
   python build_download.py
   python ..\Installing\build_exe.py
   python publish_github.py
   ```

## 6. Retire the old Google key (done on 2026-10-04)

Earlier builds of the app contained your Google Drive service-account key. Anyone who has one
of those builds can open your user database with it. The app no longer needs that key, so turn
it off:

1. Open https://console.cloud.google.com/iam-admin/serviceaccounts and pick the project.
2. Open the `fast-connect` service account -> **Keys** -> delete the existing key.
3. In Google Drive, open the Fast Connect folder -> **Share**, and remove the service account.

Only if you still use `Subscription/server_control.py`: create a **new** key afterwards, save it as
`Software/App/gdrive_credentials.json`, and share the folder with the service account again.
That file stays on your computer; the build scripts refuse to ship it.

## Updating the script later

After changing `Code.gs`: **Deploy -> Manage deployments -> edit (pencil) -> Version: New version -> Deploy**.
The URL stays the same.

## How it is protected

- Passwords are stored as salted PBKDF2-SHA256 hashes (100,000 rounds). Accounts made by old app
  versions are upgraded automatically the next time they log in. Password hashes are never sent out.
- Logging in returns a signed session token (30 days). The signing secret is created by the
  script and never leaves Google.
- 10 wrong passwords lock a username for 15 minutes; 5 wrong admin passwords lock the admin page.
- FastAI requests go through the script, which holds the Gemini key (the `GEMINI_API_KEY` script
  property) and gives every account 100 units a day (chat 1, image 2, voice 3, image generation or
  video 5), with 2,000 a day for all accounts together. Guests can't use FastAI.
- The admin page gets a 30-minute token after the password is checked. Reloading the page locks it.
- Chat servers get a one-time ticket that only works for one encrypted connection, so a server
  never sees anyone's password or session token.
- `test_backend.js` in this folder tests all of the above: `node test_backend.js`.
