const DEFAULT_RPC = "http://127.0.0.1:9334/rpc";
const DEFAULT_FAUCET = "http://127.0.0.1:9494/faucet";

const rpcDisplay = document.getElementById("rpc-display");
const faucetDisplay = document.getElementById("faucet-display");
const faucetInput = document.getElementById("faucet-endpoint");
const faucetAddress = document.getElementById("faucet-address");
const faucetResult = document.getElementById("faucet-result");
const networkStatus = document.getElementById("network-status");
const rpcInput = document.getElementById("rpc-endpoint");
const rpcTokenInput = document.getElementById("rpc-token");

let rpcEndpoint = localStorage.getItem("scratchchain_rpc") || DEFAULT_RPC;
let faucetEndpoint = localStorage.getItem("scratchchain_faucet") || DEFAULT_FAUCET;
let rpcToken = localStorage.getItem("scratchchain_rpc_token") || "";

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function formatSeconds(value) {
  if (value === null || value === undefined) return "-";
  const num = Number(value);
  if (Number.isNaN(num)) return "-";
  return `${num.toFixed(2)}s`;
}

async function rpc(method, params = {}) {
  const headers = { "Content-Type": "application/json" };
  if (rpcToken) headers["X-Auth-Token"] = rpcToken;
  const res = await fetch(rpcEndpoint, {
    method: "POST",
    headers,
    body: JSON.stringify({ method, params }),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || "RPC error");
  return data.result;
}

async function loadNetwork() {
  try {
    const metrics = await rpc("get_metrics");
    setText("stat-height", metrics.height ?? "-");
    setText("stat-peers", metrics.peers ? metrics.peers.length : "-");
    setText("stat-avg", formatSeconds(metrics.avg_block_time));
    setText("stat-mempool", metrics.mempool_size ?? "-");
    networkStatus.textContent = "Network online";
  } catch (err) {
    networkStatus.textContent = "Network offline";
  }
}

async function requestFaucet() {
  const address = faucetAddress.value.trim();
  if (!address) {
    faucetResult.textContent = "Provide an address.";
    return;
  }
  faucetResult.textContent = "Requesting tokens...";
  try {
    const res = await fetch(faucetEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ address }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Faucet error");
    faucetResult.textContent = `Success! TXID: ${data.txid}`;
  } catch (err) {
    faucetResult.textContent = err.message;
  }
}

function setupReveal() {
  const elements = document.querySelectorAll("[data-reveal]");
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.2 }
  );
  elements.forEach((el) => observer.observe(el));
}

function saveRpc() {
  rpcEndpoint = rpcInput.value.trim() || DEFAULT_RPC;
  rpcToken = rpcTokenInput.value.trim();
  localStorage.setItem("scratchchain_rpc", rpcEndpoint);
  localStorage.setItem("scratchchain_rpc_token", rpcToken);
  rpcDisplay.textContent = rpcEndpoint;
  loadNetwork();
}

function saveFaucet() {
  faucetEndpoint = faucetInput.value.trim() || DEFAULT_FAUCET;
  localStorage.setItem("scratchchain_faucet", faucetEndpoint);
  faucetDisplay.textContent = faucetEndpoint;
}

function init() {
  rpcDisplay.textContent = rpcEndpoint;
  faucetDisplay.textContent = faucetEndpoint;
  faucetInput.value = faucetEndpoint;
  rpcInput.value = rpcEndpoint;
  rpcTokenInput.value = rpcToken;

  document.getElementById("faucet-submit").addEventListener("click", requestFaucet);
  document.getElementById("scroll-faucet").addEventListener("click", () => {
    document.getElementById("faucet").scrollIntoView({ behavior: "smooth" });
  });
  document.getElementById("save-rpc").addEventListener("click", saveRpc);
  document.getElementById("save-faucet").addEventListener("click", saveFaucet);

  setupReveal();
  loadNetwork();
  setInterval(loadNetwork, 7000);
}

window.addEventListener("DOMContentLoaded", init);
