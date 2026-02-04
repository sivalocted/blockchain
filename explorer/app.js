const DEFAULT_RPC = "http://127.0.0.1:9334/rpc";
const DEFAULT_INDEXER = "http://127.0.0.1:9337";
const COIN = 100000000;

let RPC = localStorage.getItem("scratchchain_rpc") || DEFAULT_RPC;
let INDEXER = localStorage.getItem("scratchchain_indexer") || DEFAULT_INDEXER;
let RPC_TOKEN = localStorage.getItem("scratchchain_rpc_token") || "";
let indexerOnline = null;
let rpcOnline = null;
let walletAddress = null;
let systemLines = [];

function normalizeRpcEndpoint(value) {
  const trimmed = (value || "").trim();
  if (!trimmed) return DEFAULT_RPC;
  if (trimmed.endsWith("/rpc")) return trimmed;
  return trimmed.replace(/\/+$/, "") + "/rpc";
}

function normalizeIndexerEndpoint(value) {
  const trimmed = (value || "").trim();
  if (!trimmed) return DEFAULT_INDEXER;
  return trimmed.replace(/\/+$/, "");
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value;
}

function formatNumber(value) {
  if (value === null || value === undefined) return "-";
  const num = Number(value);
  if (Number.isNaN(num)) return String(value);
  return new Intl.NumberFormat().format(num);
}

function formatAmount(value) {
  if (value === null || value === undefined) return "-";
  const num = Number(value);
  if (Number.isNaN(num)) return String(value);
  const coins = num / COIN;
  return coins.toLocaleString(undefined, { maximumFractionDigits: 8 });
}

function formatHash(value) {
  if (!value) return "-";
  const text = String(value);
  if (text.length <= 16) return text;
  return text.slice(0, 10) + "..." + text.slice(-6);
}

function formatSeconds(value) {
  if (!value || Number.isNaN(Number(value))) return "-";
  const num = Number(value);
  return `${num.toFixed(2)}s`;
}

function logSystem(message, level = "info") {
  const stamp = new Date().toLocaleTimeString();
  systemLines.push(`[${stamp}] ${level.toUpperCase()} ${message}`);
  if (systemLines.length > 120) systemLines = systemLines.slice(-120);
  setText("system-output", systemLines.join("\n"));
}

async function rpc(method, params = {}) {
  const headers = { "Content-Type": "application/json" };
  if (RPC_TOKEN) headers["X-Auth-Token"] = RPC_TOKEN;
  const res = await fetch(RPC, {
    method: "POST",
    headers,
    body: JSON.stringify({ method, params }),
  });
  const data = await res.json();
  if (!data.ok) {
    throw new Error(data.error || "RPC error");
  }
  return data.result;
}

async function indexerGet(path) {
  const res = await fetch(INDEXER + path);
  const data = await res.json();
  if (!data.ok) {
    throw new Error(data.error || "Indexer error");
  }
  return data.result;
}

function updateEndpointStatus() {
  const pill = document.getElementById("endpoint-status");
  if (!pill) return;
  if (rpcOnline || indexerOnline) {
    pill.classList.add("online");
    if (rpcOnline && indexerOnline) {
      pill.textContent = "RPC + Indexer online";
    } else if (rpcOnline) {
      pill.textContent = "RPC online";
    } else {
      pill.textContent = "Indexer online";
    }
  } else {
    pill.classList.remove("online");
    pill.textContent = "Disconnected";
  }
}

async function fetchMetrics() {
  let indexerData = null;
  let rpcData = null;
  try {
    indexerData = await indexerGet("/status");
    indexerOnline = true;
  } catch {
    indexerOnline = false;
  }
  try {
    rpcData = await rpc("get_metrics");
    rpcOnline = true;
  } catch {
    rpcOnline = false;
  }
  updateEndpointStatus();
  return { indexer: indexerData, rpc: rpcData };
}

async function loadStatus() {
  try {
    const { indexer, rpc: rpcStats } = await fetchMetrics();
    const merged = Object.assign({}, indexer || {}, rpcStats || {});

    setText("stat-height", formatNumber(merged.height));
    setText("stat-tip", formatHash(merged.best_tip));
    setText("stat-mempool", formatNumber(merged.mempool_size));
    setText("stat-difficulty", formatNumber(merged.difficulty));
    setText("stat-peers", rpcStats ? formatNumber((rpcStats.peers || []).length) : "-");
    setText("stat-avg", formatSeconds(merged.avg_block_time));
    setText("stat-validators", formatNumber(merged.validators));
    setText("stat-utxo", formatNumber(merged.utxo_set));
    setText("stat-contracts", formatNumber(merged.contracts));
    setText("stat-forks", formatNumber(merged.forks));
    setText("stat-mempool-bytes", formatNumber(merged.mempool_bytes));
    setText("stat-node", rpcStats ? rpcStats.node_id || "-" : "-");
  } catch (err) {
    updateEndpointStatus();
    logSystem(`Status update failed: ${err.message}`, "warn");
  }
}

async function loadBlocks() {
  const blocksEl = document.getElementById("blocks");
  if (!blocksEl) return;
  blocksEl.innerHTML = "";
  try {
    let blocks = [];
    if (indexerOnline) {
      blocks = await indexerGet("/blocks?count=8&direction=desc");
    } else {
      const info = await rpc("get_info");
      const start = Math.max(0, info.height - 7);
      const headers = await rpc("get_headers", { start, count: 8 });
      for (const header of headers.reverse()) {
        const block = await rpc("get_block_by_height", { height: header.height });
        blocks.push({
          hash: block.hash,
          height: block.header.height,
          prev_hash: block.header.prev_hash,
          timestamp: block.header.timestamp,
          txs: block.txs.length,
          gas_used: block.header.gas_used,
          merkle_root: block.header.merkle_root,
        });
      }
    }

    if (!blocks.length) {
      blocksEl.appendChild(el("div", "result", "No blocks yet."));
      return;
    }

    for (const block of blocks) {
      const card = el("div", "block-card");
      const top = el("div", "block-row");
      top.appendChild(el("span", "badge", `Height ${block.height}`));
      top.appendChild(el("span", "mono", formatHash(block.hash)));
      card.appendChild(top);
      card.appendChild(el("div", "mono", block.merkle_root));
      card.appendChild(el("div", "block-row", `Txs: ${block.txs} · Gas: ${block.gas_used}`));
      blocksEl.appendChild(card);
    }
  } catch (err) {
    blocksEl.appendChild(el("div", "result", err.message));
  }
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderJson(container, data) {
  container.innerHTML = "";
  const pre = document.createElement("pre");
  pre.className = "code";
  pre.textContent = JSON.stringify(data, null, 2);
  container.appendChild(pre);
}

async function search() {
  const input = document.getElementById("search-input");
  const query = input.value.trim();
  if (!query) return;
  const out = document.getElementById("search-results");
  out.innerHTML = "";

  try {
    if (indexerOnline) {
      const res = await indexerGet(`/search?q=${encodeURIComponent(query)}`);
      out.innerHTML = "";
      const title = el("div", "pill", `Result: ${res.type}`);
      const pre = el("pre", "code");
      pre.textContent = JSON.stringify(res.data, null, 2);
      out.appendChild(title);
      out.appendChild(pre);
      return;
    }

    if (/^\d+$/.test(query)) {
      const block = await rpc("get_block_by_height", { height: Number(query) });
      renderJson(out, block);
      return;
    }

    if (query.length >= 40) {
      try {
        const tx = await rpc("get_tx", { txid: query });
        const receipt = await rpc("get_receipt", { txid: query });
        renderJson(out, { tx, receipt });
        return;
      } catch {}
      try {
        const block = await rpc("get_block", { hash: query });
        renderJson(out, block);
        return;
      } catch {}
    }

    const history = await rpc("get_history", { address: query, limit: 20 });
    renderJson(out, history);
  } catch (err) {
    out.textContent = err.message;
  }
}

async function loadContract() {
  const id = document.getElementById("contract-call-id").value.trim();
  const out = document.getElementById("contract-output");
  if (!id) return;
  try {
    const contract = await rpc("get_contract", { contract_id: id });
    out.textContent = JSON.stringify(contract, null, 2);
  } catch (err) {
    out.textContent = err.message;
  }
}

function parseJsonInput(text, fallback) {
  const trimmed = (text || "").trim();
  if (!trimmed) return fallback;
  try {
    return JSON.parse(trimmed);
  } catch {
    return fallback;
  }
}

function parseCodeInput(text) {
  const trimmed = (text || "").trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed;
  } catch {}
  return trimmed
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

async function ensureWalletAddress(path) {
  if (!path) return null;
  if (walletAddress) return walletAddress;
  try {
    const info = await rpc("wallet_info", { wallet: path });
    walletAddress = info.address;
    return walletAddress;
  } catch (err) {
    logSystem(`Unable to load wallet info: ${err.message}`, "warn");
    return null;
  }
}

async function refreshWallet() {
  const path = document.getElementById("wallet-path").value.trim();
  const address = await ensureWalletAddress(path);
  if (!address) return;
  setText("wallet-address", address);
  try {
    const bal = await rpc("get_balance", { address });
    const stake = await rpc("get_stake", { address });
    setText("wallet-balance", formatAmount(bal.balance));
    setText("wallet-stake", formatAmount(stake.stake));
  } catch (err) {
    logSystem(`Wallet refresh failed: ${err.message}`, "warn");
  }
}

async function walletCreate() {
  const path = document.getElementById("wallet-path").value.trim();
  if (!path) {
    setText("wallet-result", "Provide a wallet path.");
    return;
  }
  try {
    const info = await rpc("create_wallet", { wallet: path });
    walletAddress = info.address;
    setText("wallet-address", info.address);
    setText("wallet-result", `Wallet created: ${info.address}`);
    await refreshWallet();
  } catch (err) {
    setText("wallet-result", err.message);
  }
}

async function walletLoad() {
  const path = document.getElementById("wallet-path").value.trim();
  if (!path) {
    setText("wallet-result", "Provide a wallet path.");
    return;
  }
  try {
    const info = await rpc("wallet_info", { wallet: path });
    walletAddress = info.address;
    setText("wallet-address", info.address);
    setText("wallet-result", `Wallet loaded: ${info.address}`);
    await refreshWallet();
  } catch (err) {
    setText("wallet-result", err.message);
  }
}

async function walletMine() {
  const path = document.getElementById("wallet-path").value.trim();
  if (!path) {
    setText("wallet-result", "Provide a wallet path.");
    return;
  }
  try {
    const res = await rpc("mine", { wallet: path });
    setText("wallet-result", `Mined block ${res.height}: ${formatHash(res.hash)}`);
    await refreshWallet();
    await loadBlocks();
  } catch (err) {
    setText("wallet-result", err.message);
  }
}

async function walletSend() {
  const path = document.getElementById("wallet-path").value.trim();
  const to = document.getElementById("send-to").value.trim();
  const amount = document.getElementById("send-amount").value.trim();
  const fee = document.getElementById("send-fee").value.trim();
  if (!path || !to || !amount) {
    setText("wallet-result", "Wallet path, recipient, and amount are required.");
    return;
  }
  try {
    const params = { wallet: path, to, amount };
    if (fee) params.fee = fee;
    const res = await rpc("send", params);
    setText("wallet-result", `TX sent: ${res.txid}`);
  } catch (err) {
    setText("wallet-result", err.message);
  }
}

async function walletStake() {
  const path = document.getElementById("wallet-path").value.trim();
  const amount = document.getElementById("stake-amount").value.trim();
  if (!path || !amount) {
    setText("wallet-result", "Wallet path and amount are required.");
    return;
  }
  try {
    const res = await rpc("stake", { wallet: path, amount });
    setText("wallet-result", `Stake tx: ${res.txid}`);
  } catch (err) {
    setText("wallet-result", err.message);
  }
}

async function walletUnstake() {
  const path = document.getElementById("wallet-path").value.trim();
  const amount = document.getElementById("unstake-amount").value.trim();
  if (!path || !amount) {
    setText("wallet-result", "Wallet path and amount are required.");
    return;
  }
  try {
    const res = await rpc("unstake", { wallet: path, amount });
    setText("wallet-result", `Unstake tx: ${res.txid}`);
  } catch (err) {
    setText("wallet-result", err.message);
  }
}

async function loadHistory() {
  const address = document.getElementById("history-address").value.trim();
  const out = document.getElementById("history-output");
  if (!address) {
    out.textContent = "[]";
    return;
  }
  try {
    const history = await rpc("get_history", { address, limit: 30 });
    out.textContent = JSON.stringify(history, null, 2);
  } catch (err) {
    out.textContent = err.message;
  }
}

async function loadValidators() {
  const table = document.getElementById("validator-table");
  if (!table) return;
  table.innerHTML = "";
  try {
    const validators = await rpc("get_validators");
    const head = el("div", "table-row table-head");
    ["Address", "Stake", "Active", "Meta"].forEach((label) => {
      head.appendChild(el("div", null, label));
    });
    table.appendChild(head);
    if (!validators.length) {
      table.appendChild(el("div", "result", "No validators yet."));
      return;
    }
    validators.forEach((val) => {
      const row = el("div", "table-row");
      row.appendChild(el("div", "mono", val.address));
      row.appendChild(el("div", null, formatAmount(val.stake)));
      row.appendChild(el("div", null, val.active ? "Active" : "Idle"));
      row.appendChild(el("div", "mono", JSON.stringify(val.meta || {})));
      table.appendChild(row);
    });
  } catch (err) {
    table.appendChild(el("div", "result", err.message));
  }
}

async function validatorRegister(update = false) {
  const wallet = document.getElementById("validator-wallet").value.trim();
  const name = document.getElementById("validator-name").value.trim();
  const website = document.getElementById("validator-website").value.trim();
  const commission = document.getElementById("validator-commission").value.trim();
  const fee = document.getElementById("validator-fee").value.trim();
  if (!wallet) {
    setText("validator-result", "Validator wallet path required.");
    return;
  }
  const params = { wallet, name, website };
  if (commission) params.commission = Number(commission);
  if (fee) params.fee = fee;
  try {
    const method = update ? "validator_update" : "validator_register";
    const res = await rpc(method, params);
    setText("validator-result", `Validator tx: ${res.txid}`);
    await loadValidators();
  } catch (err) {
    setText("validator-result", err.message);
  }
}

async function loadGovernance() {
  const out = document.getElementById("gov-output");
  if (!out) return;
  try {
    const gov = await rpc("get_governance");
    out.textContent = JSON.stringify(gov, null, 2);
  } catch (err) {
    out.textContent = err.message;
  }
}

async function submitGovernance() {
  const wallet = document.getElementById("gov-wallet").value.trim();
  const paramsText = document.getElementById("gov-params").value;
  const result = document.getElementById("gov-result");
  if (!wallet) {
    result.textContent = "Wallet path required.";
    return;
  }
  const params = parseJsonInput(paramsText, null);
  if (!params || typeof params !== "object") {
    result.textContent = "Invalid params JSON.";
    return;
  }
  try {
    const res = await rpc("gov_update", { wallet, params });
    result.textContent = `Governance tx: ${res.txid}`;
    await loadGovernance();
  } catch (err) {
    result.textContent = err.message;
  }
}

async function contractCreate() {
  const wallet = document.getElementById("contract-wallet").value.trim();
  const codeText = document.getElementById("contract-code").value;
  const storageText = document.getElementById("contract-storage").value;
  const gasLimit = document.getElementById("contract-gas-limit").value.trim();
  const gasPrice = document.getElementById("contract-gas-price").value.trim();
  const out = document.getElementById("contract-create-result");
  if (!wallet) {
    out.textContent = "Wallet path required.";
    return;
  }
  const code = parseCodeInput(codeText);
  if (!code.length) {
    out.textContent = "Provide contract code.";
    return;
  }
  const storage = parseJsonInput(storageText, {});
  const params = { wallet, code, storage, gas_limit: Number(gasLimit || 0), gas_price: Number(gasPrice || 0) };
  try {
    const res = await rpc("contract_create", params);
    out.textContent = `Contract create tx: ${res.txid}`;
  } catch (err) {
    out.textContent = err.message;
  }
}

async function contractCall() {
  const wallet = document.getElementById("contract-call-wallet").value.trim();
  const contractId = document.getElementById("contract-call-id").value.trim();
  const calldataText = document.getElementById("contract-call-data").value;
  const gasLimit = document.getElementById("contract-call-gas-limit").value.trim();
  const gasPrice = document.getElementById("contract-call-gas-price").value.trim();
  const out = document.getElementById("contract-output");
  if (!wallet || !contractId) {
    out.textContent = "Wallet path and contract id required.";
    return;
  }
  const calldata = parseJsonInput(calldataText, []);
  const params = {
    wallet,
    contract_id: contractId,
    calldata,
    gas_limit: Number(gasLimit || 0),
    gas_price: Number(gasPrice || 0),
  };
  try {
    const res = await rpc("contract_call", params);
    out.textContent = `Contract call tx: ${res.txid}`;
  } catch (err) {
    out.textContent = err.message;
  }
}

async function loadNetwork() {
  try {
    const metrics = await rpc("get_metrics");
    setText("peer-list", JSON.stringify(metrics.peers || [], null, 2));
    setText("known-peer-list", JSON.stringify(metrics.known_peers || [], null, 2));
    setText("banscore-list", JSON.stringify(metrics.banscore || {}, null, 2));
  } catch (err) {
    setText("peer-list", "RPC offline");
    setText("known-peer-list", "RPC offline");
    setText("banscore-list", "RPC offline");
  }
}

async function snapshotCreate() {
  const path = document.getElementById("snapshot-create-path").value.trim();
  try {
    const res = await rpc("snapshot_create", path ? { path } : {});
    setText("snapshot-result", `Snapshot saved: ${res.path}`);
  } catch (err) {
    setText("snapshot-result", err.message);
  }
}

async function snapshotLoad() {
  const path = document.getElementById("snapshot-load-path").value.trim();
  if (!path) {
    setText("snapshot-result", "Provide snapshot path.");
    return;
  }
  try {
    await rpc("snapshot_load", { path });
    setText("snapshot-result", "Snapshot loaded.");
  } catch (err) {
    setText("snapshot-result", err.message);
  }
}

async function proofCreate() {
  const block = document.getElementById("proof-block").value.trim();
  const txid = document.getElementById("proof-txid").value.trim();
  const out = document.getElementById("proof-output");
  if (!block || !txid) {
    out.textContent = "Provide block hash and txid.";
    return;
  }
  try {
    const proof = await rpc("get_tx_proof", { block_hash: block, txid });
    out.textContent = JSON.stringify(proof, null, 2);
  } catch (err) {
    out.textContent = err.message;
  }
}

async function proofVerify() {
  const out = document.getElementById("proof-output");
  try {
    const proof = JSON.parse(out.textContent);
    if (!proof || !proof.root || !proof.proof || !proof.txid) {
      out.textContent = "No proof loaded to verify.";
      return;
    }
    const res = await rpc("verify_tx_proof", { txid: proof.txid, root: proof.root, proof: proof.proof });
    out.textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    out.textContent = err.message;
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
    { threshold: 0.15 }
  );
  elements.forEach((el) => observer.observe(el));
}

function setupEndpoints() {
  document.getElementById("rpc-input").value = RPC;
  document.getElementById("indexer-input").value = INDEXER;
  document.getElementById("rpc-token").value = RPC_TOKEN;
  document.getElementById("save-endpoints").addEventListener("click", () => {
    RPC = normalizeRpcEndpoint(document.getElementById("rpc-input").value);
    INDEXER = normalizeIndexerEndpoint(document.getElementById("indexer-input").value);
    RPC_TOKEN = document.getElementById("rpc-token").value.trim();
    localStorage.setItem("scratchchain_rpc", RPC);
    localStorage.setItem("scratchchain_indexer", INDEXER);
    localStorage.setItem("scratchchain_rpc_token", RPC_TOKEN);
    indexerOnline = null;
    rpcOnline = null;
    updateEndpointStatus();
    logSystem(`Endpoints saved. RPC=${RPC} INDEXER=${INDEXER}`);
    refreshAll();
  });
}

async function refreshAll() {
  await loadStatus();
  await loadBlocks();
  await loadValidators();
  await loadGovernance();
  await loadNetwork();
}

window.addEventListener("DOMContentLoaded", () => {
  setupReveal();
  setupEndpoints();

  document.getElementById("refresh-btn").addEventListener("click", refreshAll);
  document.getElementById("search-btn").addEventListener("click", search);
  document.getElementById("wallet-create").addEventListener("click", walletCreate);
  document.getElementById("wallet-load").addEventListener("click", walletLoad);
  document.getElementById("wallet-refresh").addEventListener("click", refreshWallet);
  document.getElementById("wallet-mine").addEventListener("click", walletMine);
  document.getElementById("send-btn").addEventListener("click", walletSend);
  document.getElementById("stake-btn").addEventListener("click", walletStake);
  document.getElementById("unstake-btn").addEventListener("click", walletUnstake);
  document.getElementById("history-btn").addEventListener("click", loadHistory);
  document.getElementById("validators-refresh").addEventListener("click", loadValidators);
  document.getElementById("validator-register").addEventListener("click", () => validatorRegister(false));
  document.getElementById("validator-update").addEventListener("click", () => validatorRegister(true));
  document.getElementById("gov-refresh").addEventListener("click", loadGovernance);
  document.getElementById("gov-submit").addEventListener("click", submitGovernance);
  document.getElementById("contract-create").addEventListener("click", contractCreate);
  document.getElementById("contract-call").addEventListener("click", contractCall);
  document.getElementById("contract-load").addEventListener("click", loadContract);
  document.getElementById("network-refresh").addEventListener("click", loadNetwork);
  document.getElementById("snapshot-create").addEventListener("click", snapshotCreate);
  document.getElementById("snapshot-load").addEventListener("click", snapshotLoad);
  document.getElementById("proof-create").addEventListener("click", proofCreate);
  document.getElementById("proof-verify").addEventListener("click", proofVerify);

  refreshAll();
  setInterval(loadStatus, 5000);
  setInterval(loadBlocks, 7000);
  setInterval(loadValidators, 15000);
  setInterval(loadGovernance, 20000);
  setInterval(loadNetwork, 12000);
});
