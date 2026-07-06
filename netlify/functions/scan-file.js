// VirusTotal API - File Upload Scanner
// developer: K CeY | DevRabbitZz | team: Team Akira
// Accepts a base64-encoded file (JSON body) and submits it to VirusTotal.
// Max ~32MB via the public API's direct /files endpoint.

const VT_BASE = "https://www.virustotal.com/api/v3";

function meta() {
  return {
    developer: "K CeY | DevRabbitZz",
    team: "Team Akira",
    api: "VirusTotal",
    poweredBy: "VirusTotal Public API v3"
  };
}

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "POST, OPTIONS"
    },
    body: JSON.stringify(body, null, 2)
  };
}

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return json(200, { ok: true });
  if (event.httpMethod !== "POST") {
    return json(405, { success: false, error: "Use POST.", ...meta() });
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) {
    return json(500, {
      success: false,
      error: "Server misconfigured: VT_API_KEY environment variable is missing.",
      ...meta()
    });
  }

  try {
    const { file_base64, file_name } = JSON.parse(event.body || "{}");

    if (!file_base64 || !file_name) {
      return json(400, {
        success: false,
        error: "Missing 'file_base64' and/or 'file_name' in request body.",
        example: { file_name: "test.apk", file_base64: "<base64 string>" },
        ...meta()
      });
    }

    const buffer = Buffer.from(file_base64, "base64");
    if (buffer.length > 32 * 1024 * 1024) {
      return json(400, {
        success: false,
        error: "File too large. Public VirusTotal API supports up to 32MB via direct upload.",
        ...meta()
      });
    }

    const form = new FormData();
    form.append("file", new Blob([buffer]), file_name);

    const uploadRes = await fetch(`${VT_BASE}/files`, {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: form
    });
    const uploadData = await uploadRes.json();
    if (!uploadRes.ok) {
      throw new Error(uploadData?.error?.message || `VirusTotal upload error (${uploadRes.status})`);
    }

    const analysisId = uploadData.data.id;

    // Poll briefly for a completed result (VT scans usually take 10-60s)
    let analysis;
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r, 3000));
      const res = await fetch(`${VT_BASE}/analyses/${analysisId}`, {
        headers: { "x-apikey": apiKey }
      });
      analysis = await res.json();
      if (analysis.data?.attributes?.status === "completed") break;
    }

    const attrs = analysis.data.attributes;
    const stats = attrs.stats || {};
    const sha256 = attrs.results
      ? Object.values(attrs.results)[0]?.engine_version && analysis.meta?.file_info?.sha256
      : null;
    const fileSha256 = analysis.meta?.file_info?.sha256 || null;

    return json(200, {
      success: true,
      file_name,
      status: attrs.status,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total_engines: Object.values(stats).reduce((a, b) => a + b, 0),
      verdict:
        (stats.malicious || 0) > 0
          ? "malicious"
          : (stats.suspicious || 0) > 0
          ? "suspicious"
          : "clean",
      sha256: fileSha256,
      vt_link: fileSha256 ? `https://www.virustotal.com/gui/file/${fileSha256}` : null,
      note:
        attrs.status !== "completed"
          ? "Scan still in progress on VirusTotal's side. Use /scan with type=file_hash and this sha256 to re-check shortly."
          : undefined,
      ...meta()
    });
  } catch (err) {
    return json(500, {
      success: false,
      error: err.message || "Unexpected server error.",
      ...meta()
    });
  }
};
