// VirusTotal API - powered by VirusTotal
// developer: K CeY | DevRabbitZz | team: Team Akira

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
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    },
    body: JSON.stringify(body, null, 2)
  };
}

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") {
    return json(200, { ok: true });
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
    const params = event.httpMethod === "GET"
      ? event.queryStringParameters || {}
      : JSON.parse(event.body || "{}");

    const { type, target } = params;

    if (!type || !target) {
      return json(400, {
        success: false,
        error: "Missing required fields: 'type' (url|domain|ip|file_hash) and 'target'.",
        example: {
          type: "url",
          target: "https://example.com"
        },
        ...meta()
      });
    }

    let result;

    if (type === "url") {
      result = await scanUrl(target, apiKey);
    } else if (type === "domain") {
      result = await lookupDomain(target, apiKey);
    } else if (type === "ip") {
      result = await lookupIp(target, apiKey);
    } else if (type === "file_hash") {
      result = await lookupFileHash(target, apiKey);
    } else {
      return json(400, {
        success: false,
        error: "Invalid 'type'. Must be one of: url, domain, ip, file_hash.",
        ...meta()
      });
    }

    return json(200, {
      success: true,
      type,
      target,
      result,
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

// ---- helpers ----

async function vtFetch(path, apiKey, options = {}) {
  const res = await fetch(`${VT_BASE}${path}`, {
    ...options,
    headers: {
      "x-apikey": apiKey,
      ...(options.headers || {})
    }
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data?.error?.message || `VirusTotal API error (${res.status})`);
  }
  return data;
}

function summarize(attributes) {
  const stats = attributes.last_analysis_stats || {};
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    total_engines: total,
    reputation: attributes.reputation ?? null,
    verdict:
      (stats.malicious || 0) > 0
        ? "malicious"
        : (stats.suspicious || 0) > 0
        ? "suspicious"
        : "clean"
  };
}

async function scanUrl(url, apiKey) {
  // Submit URL for analysis
  const submitRes = await vtFetch("/urls", apiKey, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `url=${encodeURIComponent(url)}`
  });

  const analysisId = submitRes.data.id;
  const urlId = Buffer.from(url).toString("base64").replace(/=+$/, "");

  // Fetch existing report (VT caches by URL id)
  let report;
  try {
    report = await vtFetch(`/urls/${urlId}`, apiKey);
  } catch (e) {
    // fallback: poll the analysis
    report = await vtFetch(`/analyses/${analysisId}`, apiKey);
    return {
      status: "queued_or_pending",
      analysis_id: analysisId,
      note: "Scan submitted. VirusTotal is still analyzing; re-check in a few seconds using file_hash/url lookup.",
      raw_stats: report.data?.attributes?.stats || null
    };
  }

  const attrs = report.data.attributes;
  return {
    url: attrs.url,
    final_url: attrs.last_final_url || attrs.url,
    title: attrs.title || null,
    ...summarize(attrs),
    categories: attrs.categories || {},
    last_analysis_date: attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null,
    vt_link: `https://www.virustotal.com/gui/url/${urlId}`
  };
}

async function lookupDomain(domain, apiKey) {
  const data = await vtFetch(`/domains/${encodeURIComponent(domain)}`, apiKey);
  const attrs = data.data.attributes;
  return {
    domain,
    ...summarize(attrs),
    registrar: attrs.registrar || null,
    creation_date: attrs.creation_date
      ? new Date(attrs.creation_date * 1000).toISOString()
      : null,
    categories: attrs.categories || {},
    vt_link: `https://www.virustotal.com/gui/domain/${domain}`
  };
}

async function lookupIp(ip, apiKey) {
  const data = await vtFetch(`/ip_addresses/${encodeURIComponent(ip)}`, apiKey);
  const attrs = data.data.attributes;
  return {
    ip,
    ...summarize(attrs),
    country: attrs.country || null,
    as_owner: attrs.as_owner || null,
    network: attrs.network || null,
    vt_link: `https://www.virustotal.com/gui/ip-address/${ip}`
  };
}

async function lookupFileHash(hash, apiKey) {
  const data = await vtFetch(`/files/${encodeURIComponent(hash)}`, apiKey);
  const attrs = data.data.attributes;
  return {
    file_name: (attrs.names && attrs.names[0]) || null,
    all_known_names: attrs.names || [],
    size: attrs.size || null,
    type_description: attrs.type_description || null,
    md5: attrs.md5,
    sha1: attrs.sha1,
    sha256: attrs.sha256,
    ...summarize(attrs),
    last_analysis_date: attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null,
    vt_link: `https://www.virustotal.com/gui/file/${attrs.sha256}`
  };
}
