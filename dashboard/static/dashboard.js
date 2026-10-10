const POLL_MS = 2000;

function badge(text, kind) {
  return `<span class="badge badge-${kind.toLowerCase()}">${text}</span>`;
}

async function refreshStats() {
  const res = await fetch("/api/stats");
  const data = await res.json();
  document.getElementById("st-firewall").textContent = data.firewall_status;
  document.getElementById("st-ids").textContent = data.ids_status;
  document.getElementById("st-response").textContent = data.auto_response_status;
  document.getElementById("stat-packets").textContent = data.packets.toLocaleString();
  document.getElementById("stat-connections").textContent = data.connections.toLocaleString();
  document.getElementById("stat-threats").textContent = data.threats.toLocaleString();
  document.getElementById("stat-blocked").textContent = data.blocked_sources.toLocaleString();
}

async function refreshAlerts() {
  const res = await fetch("/api/alerts");
  const events = await res.json();
  const body = document.getElementById("alerts-body");

  if (events.length === 0) {
    body.innerHTML = `<tr class="empty-row"><td colspan="6">No events yet &mdash; waiting for traffic&hellip;</td></tr>`;
    return;
  }

  body.innerHTML = events.map(e => `
    <tr>
      <td>${e.timestamp.split(" ")[1] || e.timestamp}</td>
      <td>${e.source_ip}</td>
      <td>${e.event_type}</td>
      <td>${e.threat_score}</td>
      <td>${badge(e.threat_level, e.threat_level)}</td>
      <td>${badge(e.action, e.action)}</td>
    </tr>
  `).join("");
}

async function refreshBlocked() {
  const res = await fetch("/api/blocked");
  const blocked = await res.json();
  const body = document.getElementById("blocked-body");

  if (blocked.length === 0) {
    body.innerHTML = `<tr class="empty-row"><td colspan="4">No active blocks</td></tr>`;
    return;
  }

  body.innerHTML = blocked.map(b => `
    <tr>
      <td>${b.ip}</td>
      <td>${b.reason}</td>
      <td>${b.score}</td>
      <td>${b.expires_in}s</td>
    </tr>
  `).join("");
}

async function loadRules() {
  const res = await fetch("/api/rules");
  const rules = await res.json();
  const body = document.getElementById("rules-body");

  body.innerHTML = rules.map(r => {
    const match = [
      r.ip ? `ip=${r.ip}` : null,
      r.protocol ? `proto=${r.protocol}` : null,
      r.port ? `port=${r.port}` : null,
    ].filter(Boolean).join(" ");
    return `<tr><td>${badge(r.action, r.action)}</td><td>${match}</td></tr>`;
  }).join("");
}

async function refreshSites() {
  const res = await fetch("/api/site-visits");
  const visits = await res.json();
  const body = document.getElementById("sites-body");

  if (visits.length === 0) {
    body.innerHTML = `<tr class="empty-row"><td colspan="3">No DNS lookups seen yet (real mode only)</td></tr>`;
    return;
  }

  body.innerHTML = visits.map(v => `
    <tr>
      <td>${v.timestamp.split(" ")[1] || v.timestamp}</td>
      <td>${v.source_ip}</td>
      <td>${v.domain}</td>
    </tr>
  `).join("");
}

async function tick() {
  try {
    await Promise.all([refreshStats(), refreshAlerts(), refreshBlocked(), refreshSites()]);
  } catch (err) {
    console.error("Dashboard refresh failed:", err);
  }
}

loadRules();
tick();
setInterval(tick, POLL_MS);
