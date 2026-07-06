# 🛡️ ViralTotal API

A powerful, serverless threat-scanning API and terminal-style web interface powered by the **VirusTotal Public API v3**. This project allows developers to host their own security scanning service to analyze URLs, domains, IP addresses, file hashes, and direct file uploads.

Built with ❤️ by **K CeY | DevRabbitZz** — **Team AKIRA**.

---

## 🚀 Features

* **Multi-Type Scanning:** Supports checking URLs, domains, IP addresses, and file hashes.
* **Direct File Uploads:** Upload files up to 32MB directly for analysis.
* **Serverless Architecture:** Fully optimized to run on **Netlify Functions** for zero-cost hosting.
* **Terminal-Style UI:** Includes a dark, hacker-themed web interface for manual testing.
* **Bot Friendly:** Easily integrated into WhatsApp, Discord, or Telegram bots.

---

## 🛠️ Deployment Guide

Follow these steps to deploy your own instance of this API in less than 5 minutes:

### 1. Fork & Clone
Fork this repository to your GitHub profile and clone it locally, or download the source files.

### 2. Deploy to Netlify
1. Log in to your [Netlify Dashboard](https://app.netlify.com/).
2. Click **Add new site** → **Import an existing project**.
3. Connect your GitHub account and select this repository.
4. The build settings are pre-configured via `netlify.toml`, so click **Deploy**.

### 3. Configure Environment Variables
To connect to VirusTotal, you must supply your private API key:
1. Go to your site dashboard on Netlify: **Site configuration** → **Environment variables**.
2. Click **Add a variable** and set:
   * **Key:** `VT_API_KEY`
   * **Value:** `YOUR_VIRUSTOTAL_API_KEY` *(Get one for free at [VirusTotal](https://www.virustotal.com/gui/join-us))*
3. Trigger a new deploy to apply the changes.

> ⚠️ **Warning:** Never hardcode your API key inside the repository files. Keep it securely inside Netlify's environment variables.

---

## 🔌 API Endpoints Documentation

Once deployed, your base URL will look like: `https://your-site-name.netlify.app`

### 1. Standard Scan (URL / Domain / IP / Hash)
Analyzes web entities or standard MD5/SHA-256 file hashes.

* **Endpoint:** `/.netlify/functions/scan`
* **Methods Supported:** `GET` or `POST`

#### POST Request Example
```json
// Headers: Content-Type: application/json
{
  "type": "url", 
  "target": "[https://example.com](https://example.com)"
}
