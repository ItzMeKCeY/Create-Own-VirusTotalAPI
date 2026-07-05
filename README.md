# ViralTotal API

URL / Domain / IP / File-hash / File-upload threat scanner, powered by VirusTotal's public API v3.
Built by **K CeY | DevRabbitZz** — **Team Akira**.

## 1. Deploy to Netlify

1. Push this folder to a GitHub repo (or drag-and-drop the folder into Netlify's dashboard).
2. In Netlify: **Add new site → Import an existing project** → pick this repo.
3. Build settings are already set in `netlify.toml` — no changes needed.
4. **Before first deploy (or right after), set your environment variable:**
   - Go to **Site configuration → Environment variables**
   - Add: `VT_API_KEY` = *your VirusTotal API key*
   - ⚠️ Get a fresh key from https://www.virustotal.com/gui/join-us → profile icon → API Key.
     **Never share this key in chat, screenshots, or public repos.** If a key is ever exposed, regenerate it immediately from the same page.
5. Deploy. Netlify gives you a live URL like `https://your-site-name.netlify.app`.

## 2. Test it live

Open your Netlify URL in a browser — the dark terminal-style UI lets you test URL, domain, IP, hash, and file-upload scans directly.

## 3. API Endpoints (for WhatsApp bots / any client)

### Scan a URL / Domain / IP / Hash
```
POST https://your-site-name.netlify.app/.netlify/functions/scan
Content-Type: application/json

{
  "type": "url",       // "url" | "domain" | "ip" | "file_hash"
  "target": "https://example.com"
}
```

GET also works:
```
GET /.netlify/functions/scan?type=url&target=https://example.com
```

### Scan an uploaded file
```
POST https://your-site-name.netlify.app/.netlify/functions/scan-file
Content-Type: application/json

{
  "file_name": "app.apk",
  "file_base64": "<base64 encoded file content>"
}
```

### Example response
```json
{
  "success": true,
  "type": "url",
  "target": "https://example.com",
  "result": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 68,
    "undetected": 5,
    "total_engines": 73,
    "verdict": "clean",
    "vt_link": "https://www.virustotal.com/gui/url/..."
  },
  "developer": "K CeY | DevRabbitZz",
  "team": "Team Akira",
  "api": "ViralTotal"
}
```

## 4. WhatsApp bot integration (Baileys example)

```js
const axios = require("axios");

async function scanLink(url) {
  const { data } = await axios.post(
    "https://your-site-name.netlify.app/.netlify/functions/scan",
    { type: "url", target: url }
  );
  return data;
}

// inside your message handler:
if (text.startsWith(".scan ")) {
  const url = text.slice(6).trim();
  const data = await scanLink(url);
  if (!data.success) {
    await sock.sendMessage(from, { text: `⚠️ ${data.error}` });
    return;
  }
  const r = data.result;
  await sock.sendMessage(from, {
    text:
      `🛡️ *ViralTotal Scan*\n` +
      `Verdict: *${r.verdict.toUpperCase()}*\n` +
      `Malicious: ${r.malicious} | Suspicious: ${r.suspicious} | Clean: ${r.harmless}\n` +
      `Engines: ${r.total_engines}\n` +
      (r.vt_link ? `Report: ${r.vt_link}` : "")
  });
}
```

## 5. Notes & limits

- Uses VirusTotal's **free public API**: 4 requests/minute, 500/day, 15,500/month. Fine for bot/personal use; not for high-traffic commercial products (VT's paid tier is needed for that).
- File upload endpoint supports files up to **32MB** (public API direct-upload limit).
- Scans that are still processing return `status: "queued_or_pending"` — re-check with the `file_hash` type once VT finishes (usually 10–60s).
- This project only talks to VirusTotal's official API — no scraping, so it stays within their Terms of Service and stays reliable long-term.

---
**developer:** K CeY | DevRabbitZz &nbsp;|&nbsp; **team:** Team Akira
