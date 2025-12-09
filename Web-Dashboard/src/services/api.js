// src/services/api.js
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function post(path, body) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `API ${path} failed (${res.status}): ${text || res.statusText}`
    );
  }

  return res.json();
}

async function get(path) {
  const res = await fetch(`${API_BASE_URL}${path}`);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `API ${path} failed (${res.status}): ${text || res.statusText}`
    );
  }
  return res.json();
}

/**
 * Detect scam probability cho 1 account
 * Backend: POST /detect/account  
 */
export function detectAccount(accountAddress, options = {}) {
  return post("/detect/account", {
    account_address: accountAddress,
    explain: true,
    explain_with_llm: true,
    max_transactions: 1000,
    ...options,
  });
}

/**
 * Lấy transaction history của 1 address
 * Backend: GET /account/{address}/transactions
 */
export function fetchAccountTransactions(
  address,
  { page = 1, limit = 50 } = {}
) {
  const qs = new URLSearchParams({
    page: String(page),
    limit: String(limit),
  }).toString();

  return get(`/account/${address}/transactions?${qs}`);
}

export function fetchAccountApprovals(address, { page = 1, limit = 200 } = {}) {
  const qs = new URLSearchParams({
    page: String(page),
    limit: String(limit),
  }).toString();

  return get(`/account/${address}/approvals?${qs}`);
}


/**
 * Detect scam cho 1 transaction theo hash
 * Backend: POST /detect/transaction
 * Trả về object có field transaction_scam_probability
 */
export function detectTransactionByHash(txHash, options = {}) {
  return post("/detect/transaction", {
    transaction_hash: txHash,
    // để UI nhanh hơn: mặc định không cần SHAP / LLM
    explain: false,
    explain_with_llm: false,
    ...options,
  });
}

/**
 * Detect risk cho cả 1 page transactions và trả về list đã gắn risk_score
 * Dùng cho cột "Risk" trong TransactionMonitorPage
 */
export async function detectTransactionsRisk(address, transactions) {
  if (!transactions || !transactions.length) return [];

  // Gọi lần lượt để tránh bắn quá nhiều request song song tới backend/Etherscan
  const riskByHash = new Map();

  for (const tx of transactions) {
    try {
      const res = await detectTransactionByHash(tx.hash);
      const prob = res?.transaction_scam_probability;
      if (typeof prob === "number") {
        riskByHash.set(tx.hash, prob);
      }
    } catch (e) {
      console.error("detectTransactionsRisk failed for", tx.hash, e);
      // bỏ qua tx lỗi, vẫn hiển thị bình thường
    }
  }

  // Gắn risk_score vào từng tx (0–1)
  return transactions.map((tx) => ({
    ...tx,
    risk_score:
      riskByHash.has(tx.hash) ? riskByHash.get(tx.hash) : tx.risk_score ?? null,
  }));
}
