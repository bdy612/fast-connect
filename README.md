# Fast Connect

Encrypted chat with a built-in AI assistant (FastAI) for Windows, macOS and Linux.

This repository is the Fast Connect website, published with GitHub Pages:

- `index.html`, `features.html`, `download.html`: the public pages
- `login.html`, `signup.html`, `account.html`: accounts (the same accounts as the desktop app)
- `admin.html`: account management, protected by the admin password
- `downloads/`: the macOS / Linux `.zip` and the SHA-256 checksums of both downloads
- The Windows setup `.exe` is attached to the latest
  [GitHub Release](https://github.com/bdy612/fast-connect/releases/latest)
- `backend/`: the Google Apps Script that stores accounts and runs FastAI (see `backend/SETUP.md`)

No passwords or keys are stored in this repository. The admin password, the Gemini key and the
session signing secret live only in the Apps Script project's properties.

## Publishing

1. Push this folder to a GitHub repository.
2. In the repository, open **Settings -> Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, branch `main`, folder `/ (root)`, and click **Save**.
4. After a minute the site is live at `https://<your-username>.github.io/<repository-name>/`.

## License

MIT. See `LICENSE`.
