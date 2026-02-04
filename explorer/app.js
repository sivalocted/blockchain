const RPC = "http://127.0.0.1:9334/rpc";
const INDEXER = "http://127.0.0.1:9337";
let indexerOnline = null;

async function rpc(method, params = {}) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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

async function ensureIndexer() {
  if (indexerOnline !== null) return indexerOnline;
  try {
    await indexerGet("/status");
    indexerOnline = true;
  } catch {
    indexerOnline = false;
  }
  return indexerOnline;
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text) node.textContent = text;
  return node;
}

async function loadStatus() {
  try {
    let info;
    if (await ensureIndexer()) {
      info = await indexerGet("/status");
    } else {
      info = await rpc("get_info");
    }
    document.getElementById("stat-height").textContent = info.height;
    document.getElementById("stat-tip").textContent = info.best_tip || "-";
    document.getElementById("stat-mempool").textContent = info.mempool_size;
  } catch (err) {
    document.getElementById("stat-tip").textContent = "RPC offline";
  }
}

async function loadBlocks() {
  const blocksEl = document.getElementById("blocks");
  blocksEl.innerHTML = "";
  try {
    if (await ensureIndexer()) {
      const blocks = await indexerGet("/blocks?count=6&direction=desc");
      for (const block of blocks) {
        const card = el("div", "block-card");
        const top = el("div", "block-row");
        top.appendChild(el("span", "badge", `Height ${block.height}`));
        top.appendChild(el("span", "mono", block.prev_hash.slice(0, 16) + "..."));
        card.appendChild(top);
        card.appendChild(el("div", "mono", block.merkle_root));
        card.appendChild(el("div", "block-row", `Txs: ${block.txs} · Gas: ${block.gas_used}`));
        blocksEl.appendChild(card);
      }
    } else {
      const info = await rpc("get_info");
      const start = Math.max(0, info.height - 5);
      const headers = await rpc("get_headers", { start, count: 6 });
      for (const header of headers.reverse()) {
        const block = await rpc("get_block_by_height", { height: header.height });
        const card = el("div", "block-card");
        const top = el("div", "block-row");
        top.appendChild(el("span", "badge", `Height ${block.header.height}`));
        top.appendChild(el("span", "mono", block.header.prev_hash.slice(0, 16) + "..."));
        card.appendChild(top);
        card.appendChild(el("div", "mono", block.header.merkle_root));
        card.appendChild(el("div", "block-row", `Txs: ${block.txs.length} · Gas: ${block.header.gas_used}`));
        blocksEl.appendChild(card);
      }
    }
  } catch (err) {
    blocksEl.appendChild(el("div", "result", "RPC offline or no blocks yet."));
  }
}

async function search() {
  const input = document.getElementById("search-input");
  const query = input.value.trim();
  if (!query) return;
  const out = document.getElementById("search-results");
  out.innerHTML = "";

  const result = el("div", "result");
  try {
    if (await ensureIndexer()) {
      const res = await indexerGet(`/search?q=${encodeURIComponent(query)}`);
      result.appendChild(el("h3", null, res.type === "address" ? "Address History" : res.type));
      result.appendChild(el("pre", "code", JSON.stringify(res.data, null, 2)));
      out.appendChild(result);
      return;
    }

    if (query.length >= 40) {
      // try tx
      try {
        const tx = await rpc("get_tx", { txid: query });
        result.appendChild(el("h3", null, "Transaction"));
        result.appendChild(el("pre", "code", JSON.stringify(tx, null, 2)));
        try {
          const receipt = await rpc("get_receipt", { txid: query });
          result.appendChild(el("h3", null, "Receipt"));
          result.appendChild(el("pre", "code", JSON.stringify(receipt, null, 2)));
        } catch {}
        out.appendChild(result);
        return;
      } catch {}

      // try block
      try {
        const block = await rpc("get_block", { hash: query });
        result.appendChild(el("h3", null, "Block"));
        result.appendChild(el("pre", "code", JSON.stringify(block, null, 2)));
        out.appendChild(result);
        return;
      } catch {}
    }

    // try address history
    const history = await rpc("get_history", { address: query, limit: 20 });
    result.appendChild(el("h3", null, "Address History"));
    result.appendChild(el("pre", "code", JSON.stringify(history, null, 2)));
    out.appendChild(result);
  } catch (err) {
    out.appendChild(el("div", "result", err.message));
  }
}

async function loadContract() {
  const id = document.getElementById("contract-input").value.trim();
  const out = document.getElementById("contract-output");
  if (!id) return;
  try {
    const contract = await rpc("get_contract", { contract_id: id });
    out.textContent = JSON.stringify(contract, null, 2);
  } catch (err) {
    out.textContent = err.message;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  loadStatus();
  loadBlocks();
  document.getElementById("search-btn").addEventListener("click", search);
  document.getElementById("contract-btn").addEventListener("click", loadContract);
  setInterval(loadStatus, 5000);
  setInterval(loadBlocks, 7000);
});
