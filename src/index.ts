#!/usr/bin/env node
/**
 * base-security-scanner-mcp -- MCP server for scanning smart contracts on Base mainnet.
 *
 * Tools:
 *   scan_contract          -- Analyze a contract for security issues
 *   check_honeypot         -- Check if a token is a honeypot
 *   detect_rug_risk        -- Score rug pull risk 0-100
 *   analyze_bytecode       -- Disassemble and identify contract patterns
 *   check_token_permissions -- Check owner permissions (mint, pause, blacklist, etc.)
 *   get_contract_info      -- Basic contract metadata
 *   compare_bytecode       -- Clone detection between two contracts
 *   audit_report           -- Full security audit report
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { ethers } from "ethers";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const RPC_URL = process.env.RPC_URL || "https://mainnet.base.org";
const provider = new ethers.JsonRpcProvider(RPC_URL);

const UNISWAP_V2_ROUTER = "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24";
const WETH = "0x4200000000000000000000000000000000000006";

// ---------------------------------------------------------------------------
// Known function selectors (4-byte)
// ---------------------------------------------------------------------------

const KNOWN_SELECTORS: Record<string, { name: string; risk: string; description: string }> = {
  "40c10f19": { name: "mint(address,uint256)", risk: "critical", description: "Owner can mint unlimited tokens" },
  "8456cb59": { name: "pause()", risk: "high", description: "Owner can pause all transfers" },
  "44337ea1": { name: "blacklist(address)", risk: "high", description: "Owner can blacklist addresses" },
  "69fe0e2d": { name: "setFee(uint256)", risk: "high", description: "Owner can change fee to 100%" },
  "715018a6": { name: "renounceOwnership()", risk: "info", description: "Ownership can be renounced (good)" },
  "8da5cb5b": { name: "owner()", risk: "info", description: "Contract has an owner" },
  "f2fde38b": { name: "transferOwnership(address)", risk: "medium", description: "Ownership can be transferred" },
  "a9059cbb": { name: "transfer(address,uint256)", risk: "info", description: "Standard ERC-20 transfer" },
  "23b872dd": { name: "transferFrom(address,address,uint256)", risk: "info", description: "Standard ERC-20 transferFrom" },
  "095ea7b3": { name: "approve(address,uint256)", risk: "info", description: "Standard ERC-20 approve" },
  "dd62ed3e": { name: "allowance(address,address)", risk: "info", description: "Standard ERC-20 allowance" },
  "70a08231": { name: "balanceOf(address)", risk: "info", description: "Standard ERC-20 balanceOf" },
  "18160ddd": { name: "totalSupply()", risk: "info", description: "Standard ERC-20 totalSupply" },
  "3659cfe6": { name: "upgradeTo(address)", risk: "critical", description: "Proxy upgrade — code can change" },
  "4f1ef286": { name: "upgradeToAndCall(address,bytes)", risk: "critical", description: "Proxy upgrade with call" },
  "5c60da1b": { name: "implementation()", risk: "medium", description: "Proxy pattern detected" },
  "c4d66de8": { name: "initialize(address)", risk: "medium", description: "Initializer (proxy pattern)" },
  "52d1902d": { name: "proxiableUUID()", risk: "medium", description: "UUPS proxy pattern" },
  "f851a440": { name: "admin()", risk: "medium", description: "Proxy admin function" },
  "e30c3978": { name: "pendingOwner()", risk: "info", description: "Two-step ownership transfer" },
  "a457c2d7": { name: "decreaseAllowance(address,uint256)", risk: "info", description: "Safe allowance decrease" },
  "39509351": { name: "increaseAllowance(address,uint256)", risk: "info", description: "Safe allowance increase" },
  "42966c68": { name: "burn(uint256)", risk: "info", description: "Token burn function" },
  "79cc6790": { name: "burnFrom(address,uint256)", risk: "medium", description: "Can burn others' tokens" },
  "e4748b9e": { name: "setMaxTxAmount(uint256)", risk: "high", description: "Owner can restrict max tx" },
  "8ee88c53": { name: "setMaxWalletSize(uint256)", risk: "high", description: "Owner can restrict max wallet" },
  "c0246668": { name: "excludeFromFees(address,bool)", risk: "medium", description: "Fee exclusion control" },
  "1694505e": { name: "setAutomatedMarketMakerPair(address,bool)", risk: "medium", description: "AMM pair control" },
  "49bd5a5e": { name: "uniswapV2Pair()", risk: "info", description: "Has Uniswap pair reference" },
  "1a8145bb": { name: "setTradingActive(bool)", risk: "critical", description: "Owner can disable trading" },
  "c9567bf9": { name: "openTrading()", risk: "medium", description: "One-time trading enable" },
};

// Additional selectors for pattern detection without direct risk labeling
const PATTERN_SELECTORS: Record<string, string> = {
  "d505accf": "permit (ERC-2612)",
  "3644e515": "DOMAIN_SEPARATOR",
  "7ecebe00": "nonces",
  "e9fad8ee": "exit (staking)",
  "a694fc3a": "stake",
  "2e1a7d4d": "withdraw",
  "853828b6": "withdrawAll",
  "c45a0155": "factory",
  "0dfe1681": "token0",
  "d21220a7": "token1",
  "0902f1ac": "getReserves",
  "6a627842": "mint (LP)",
  "89afcb44": "burn (LP)",
  "022c0d9f": "swap",
};

// ---------------------------------------------------------------------------
// ABIs
// ---------------------------------------------------------------------------

const ERC20_ABI = [
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)",
  "function balanceOf(address) view returns (uint256)",
  "function owner() view returns (address)",
  "function allowance(address,address) view returns (uint256)",
];

const ROUTER_ABI = [
  "function getAmountsOut(uint256,address[]) view returns (uint256[])",
  "function factory() view returns (address)",
];

const FACTORY_ABI = [
  "function getPair(address,address) view returns (address)",
];

const PAIR_ABI = [
  "function getReserves() view returns (uint112,uint112,uint32)",
  "function token0() view returns (address)",
  "function token1() view returns (address)",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ok(data: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function fail(msg: string) {
  return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }, null, 2) }], isError: true as const };
}

function serializeBigInts(obj: unknown): unknown {
  if (typeof obj === "bigint") return obj.toString();
  if (Array.isArray(obj)) return obj.map(serializeBigInts);
  if (obj !== null && typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[k] = serializeBigInts(v);
    }
    return out;
  }
  return obj;
}

/** Extract 4-byte function selectors from bytecode */
function extractSelectors(bytecode: string): string[] {
  const selectors = new Set<string>();
  // Look for PUSH4 opcode (0x63) followed by 4 bytes
  const hex = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
  for (let i = 0; i < hex.length - 10; i += 2) {
    if (hex.substring(i, i + 2) === "63") {
      const selector = hex.substring(i + 2, i + 10);
      // Filter obviously invalid selectors (all zeros, all ff, etc.)
      if (selector !== "00000000" && selector !== "ffffffff") {
        selectors.add(selector);
      }
    }
  }
  return Array.from(selectors);
}

/** Identify known opcodes in bytecode for pattern analysis */
function analyzeOpcodes(bytecode: string): {
  hasDelegatecall: boolean;
  hasSelfDestruct: boolean;
  hasCreate: boolean;
  hasCreate2: boolean;
  estimatedComplexity: string;
} {
  const hex = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
  let hasDelegatecall = false;
  let hasSelfDestruct = false;
  let hasCreate = false;
  let hasCreate2 = false;

  for (let i = 0; i < hex.length; i += 2) {
    const opcode = hex.substring(i, i + 2);
    if (opcode === "f4") hasDelegatecall = true;
    if (opcode === "ff") hasSelfDestruct = true;
    if (opcode === "f0") hasCreate = true;
    if (opcode === "f5") hasCreate2 = true;
  }

  const byteLength = hex.length / 2;
  let estimatedComplexity = "simple";
  if (byteLength > 20000) estimatedComplexity = "very complex";
  else if (byteLength > 10000) estimatedComplexity = "complex";
  else if (byteLength > 3000) estimatedComplexity = "moderate";

  return { hasDelegatecall, hasSelfDestruct, hasCreate, hasCreate2, estimatedComplexity };
}

/** Identify contract type from selectors */
function identifyContractType(selectors: string[]): string[] {
  const types: string[] = [];
  const selectorSet = new Set(selectors);

  // ERC-20
  if (selectorSet.has("a9059cbb") && selectorSet.has("70a08231") && selectorSet.has("18160ddd")) {
    types.push("ERC-20 Token");
  }
  // ERC-721
  if (selectorSet.has("6352211e") || selectorSet.has("42842e0e")) {
    types.push("ERC-721 NFT");
  }
  // ERC-1155
  if (selectorSet.has("2eb2c2d6") || selectorSet.has("f242432a")) {
    types.push("ERC-1155 Multi-Token");
  }
  // Proxy
  if (selectorSet.has("5c60da1b") || selectorSet.has("3659cfe6") || selectorSet.has("52d1902d")) {
    types.push("Proxy Contract");
  }
  // AMM Pair
  if (selectorSet.has("0902f1ac") && selectorSet.has("022c0d9f")) {
    types.push("AMM Liquidity Pair");
  }
  // AMM Router
  if (selectorSet.has("38ed1739") || selectorSet.has("7ff36ab5")) {
    types.push("AMM Router");
  }
  // Staking
  if (selectorSet.has("a694fc3a") && selectorSet.has("2e1a7d4d")) {
    types.push("Staking Contract");
  }
  // Lending
  if (selectorSet.has("c5ebeaec") || selectorSet.has("0e752702")) {
    types.push("Lending Protocol");
  }
  // Ownable
  if (selectorSet.has("8da5cb5b")) {
    types.push("Ownable");
  }
  // Diamond / ERC-2535
  if (selectorSet.has("1f931c1c") || selectorSet.has("7a0ed627")) {
    types.push("Diamond (ERC-2535)");
  }
  // ERC-2612 Permit
  if (selectorSet.has("d505accf")) {
    types.push("ERC-2612 Permit");
  }

  if (types.length === 0) types.push("Unknown");
  return types;
}

/** Safe call that returns null on failure */
async function safeCall<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Core analysis functions
// ---------------------------------------------------------------------------

async function getContractBytecode(address: string): Promise<string> {
  return await provider.getCode(address);
}

async function getBasicContractInfo(address: string): Promise<Record<string, unknown>> {
  const [code, balance, txCount] = await Promise.all([
    provider.getCode(address),
    provider.getBalance(address),
    provider.getTransactionCount(address),
  ]);

  const isContract = code !== "0x" && code.length > 2;
  const bytecodeSize = isContract ? (code.length - 2) / 2 : 0;

  return {
    address,
    isContract,
    bytecodeSize,
    balanceETH: ethers.formatEther(balance),
    balanceWei: balance.toString(),
    transactionCount: txCount,
  };
}

async function checkOwnership(address: string): Promise<{
  hasOwner: boolean;
  owner: string | null;
  isRenounced: boolean;
}> {
  const contract = new ethers.Contract(address, ERC20_ABI, provider);
  const owner = await safeCall(() => contract.owner());

  if (owner === null) {
    return { hasOwner: false, owner: null, isRenounced: false };
  }

  const isRenounced =
    owner === "0x0000000000000000000000000000000000000000" ||
    owner === "0x000000000000000000000000000000000000dEaD";

  return { hasOwner: true, owner, isRenounced };
}

async function getTokenMetadata(address: string): Promise<Record<string, unknown> | null> {
  const contract = new ethers.Contract(address, ERC20_ABI, provider);
  const [name, symbol, decimals, totalSupply] = await Promise.all([
    safeCall(() => contract.name()),
    safeCall(() => contract.symbol()),
    safeCall(() => contract.decimals()),
    safeCall(() => contract.totalSupply()),
  ]);

  if (!name && !symbol) return null;

  return {
    name: name ?? "Unknown",
    symbol: symbol ?? "???",
    decimals: decimals !== null ? Number(decimals) : 18,
    totalSupply: totalSupply !== null ? totalSupply.toString() : "0",
    totalSupplyFormatted: totalSupply !== null && decimals !== null
      ? ethers.formatUnits(totalSupply, Number(decimals))
      : "unknown",
  };
}

async function findLiquidityPair(tokenAddress: string): Promise<{
  pairAddress: string | null;
  hasLiquidity: boolean;
  reserveToken: string;
  reserveWETH: string;
}> {
  try {
    const router = new ethers.Contract(UNISWAP_V2_ROUTER, ROUTER_ABI, provider);
    const factoryAddr = await safeCall(() => router.factory());
    if (!factoryAddr) {
      return { pairAddress: null, hasLiquidity: false, reserveToken: "0", reserveWETH: "0" };
    }

    const factory = new ethers.Contract(factoryAddr, FACTORY_ABI, provider);
    const pairAddress = await safeCall(() => factory.getPair(tokenAddress, WETH));

    if (!pairAddress || pairAddress === "0x0000000000000000000000000000000000000000") {
      return { pairAddress: null, hasLiquidity: false, reserveToken: "0", reserveWETH: "0" };
    }

    const pair = new ethers.Contract(pairAddress, PAIR_ABI, provider);
    const [reserves, token0] = await Promise.all([
      safeCall(() => pair.getReserves()),
      safeCall(() => pair.token0()),
    ]);

    if (!reserves || !token0) {
      return { pairAddress, hasLiquidity: false, reserveToken: "0", reserveWETH: "0" };
    }

    const isToken0 = token0.toLowerCase() === tokenAddress.toLowerCase();
    const reserveToken = isToken0 ? reserves[0].toString() : reserves[1].toString();
    const reserveWETH = isToken0 ? reserves[1].toString() : reserves[0].toString();
    const hasLiquidity = BigInt(reserveWETH) > 0n;

    return { pairAddress, hasLiquidity, reserveToken, reserveWETH };
  } catch {
    return { pairAddress: null, hasLiquidity: false, reserveToken: "0", reserveWETH: "0" };
  }
}

async function simulateHoneypot(tokenAddress: string): Promise<{
  isHoneypot: boolean;
  canBuy: boolean;
  canSell: boolean;
  buyTax: number | null;
  sellTax: number | null;
  details: string;
}> {
  const defaultResult = {
    isHoneypot: false,
    canBuy: false,
    canSell: false,
    buyTax: null as number | null,
    sellTax: null as number | null,
    details: "",
  };

  try {
    const router = new ethers.Contract(UNISWAP_V2_ROUTER, ROUTER_ABI, provider);

    // Try to get a buy quote: ETH -> Token
    const buyAmount = ethers.parseEther("0.001");
    const buyAmounts = await safeCall(() =>
      router.getAmountsOut(buyAmount, [WETH, tokenAddress])
    );

    if (!buyAmounts || buyAmounts.length < 2) {
      return { ...defaultResult, details: "No liquidity pair found or getAmountsOut failed" };
    }

    const expectedTokens = buyAmounts[1];
    defaultResult.canBuy = BigInt(expectedTokens) > 0n;

    if (!defaultResult.canBuy) {
      return { ...defaultResult, isHoneypot: true, details: "Cannot buy: getAmountsOut returns 0 tokens" };
    }

    // Try to get a sell quote: Token -> ETH
    const sellAmounts = await safeCall(() =>
      router.getAmountsOut(expectedTokens, [tokenAddress, WETH])
    );

    if (!sellAmounts || sellAmounts.length < 2) {
      return {
        ...defaultResult,
        isHoneypot: true,
        canBuy: true,
        details: "Cannot sell: getAmountsOut reverts for sell path. Likely honeypot.",
      };
    }

    const ethBack = sellAmounts[1];
    defaultResult.canSell = BigInt(ethBack) > 0n;

    if (!defaultResult.canSell) {
      return {
        ...defaultResult,
        isHoneypot: true,
        canBuy: true,
        details: "Cannot sell: getAmountsOut returns 0 ETH. Honeypot confirmed.",
      };
    }

    // Calculate effective taxes from price impact
    const buyAmountNum = Number(ethers.formatEther(buyAmount));
    const ethBackNum = Number(ethers.formatEther(ethBack));

    // Round-trip loss approximation (includes AMM fee + any token tax)
    // Uniswap V2 fee is 0.3% per swap, so round-trip is ~0.6%
    const roundTripLoss = ((buyAmountNum - ethBackNum) / buyAmountNum) * 100;
    const estimatedTaxTotal = Math.max(0, roundTripLoss - 0.6); // subtract normal AMM fees
    const estimatedBuyTax = estimatedTaxTotal / 2;
    const estimatedSellTax = estimatedTaxTotal / 2;

    defaultResult.buyTax = Math.round(estimatedBuyTax * 100) / 100;
    defaultResult.sellTax = Math.round(estimatedSellTax * 100) / 100;

    // High tax is suspicious
    if (roundTripLoss > 50) {
      return {
        ...defaultResult,
        isHoneypot: true,
        canBuy: true,
        canSell: true,
        details: `Extreme round-trip loss: ${roundTripLoss.toFixed(1)}%. Effectively a honeypot due to excessive fees.`,
      };
    }

    if (roundTripLoss > 20) {
      defaultResult.details = `High round-trip loss: ${roundTripLoss.toFixed(1)}%. Possible soft honeypot with high fees.`;
    } else {
      defaultResult.details = `Round-trip loss: ${roundTripLoss.toFixed(1)}% (includes ~0.6% AMM fees). Appears tradeable.`;
    }

    return defaultResult;
  } catch (err) {
    return {
      ...defaultResult,
      details: `Honeypot simulation failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function analyzeSelectorRisks(selectors: string[]): {
  findings: Array<{ selector: string; name: string; risk: string; description: string }>;
  riskCounts: Record<string, number>;
} {
  const findings: Array<{ selector: string; name: string; risk: string; description: string }> = [];
  const riskCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, info: 0 };

  for (const sel of selectors) {
    const known = KNOWN_SELECTORS[sel];
    if (known) {
      findings.push({ selector: sel, ...known });
      riskCounts[known.risk] = (riskCounts[known.risk] || 0) + 1;
    }
  }

  return { findings, riskCounts };
}

async function computeRugScore(tokenAddress: string): Promise<{
  score: number;
  factors: Array<{ factor: string; impact: number; detail: string }>;
}> {
  const factors: Array<{ factor: string; impact: number; detail: string }> = [];
  let score = 0;

  // 1. Check ownership
  const ownership = await checkOwnership(tokenAddress);
  if (ownership.hasOwner && !ownership.isRenounced) {
    factors.push({ factor: "Ownership not renounced", impact: 15, detail: `Owner: ${ownership.owner}` });
    score += 15;
  } else if (ownership.isRenounced) {
    factors.push({ factor: "Ownership renounced", impact: -5, detail: "Good: ownership renounced" });
    score = Math.max(0, score - 5);
  }

  // 2. Check bytecode for dangerous selectors
  const code = await getContractBytecode(tokenAddress);
  if (code === "0x" || code.length <= 2) {
    return { score: 0, factors: [{ factor: "Not a contract", impact: 0, detail: "Address is EOA" }] };
  }

  const selectors = extractSelectors(code);
  const { findings, riskCounts } = analyzeSelectorRisks(selectors);

  if (riskCounts.critical > 0) {
    const criticals = findings.filter(f => f.risk === "critical");
    const impact = riskCounts.critical * 20;
    factors.push({
      factor: "Critical functions found",
      impact,
      detail: criticals.map(c => c.name).join(", "),
    });
    score += impact;
  }

  if (riskCounts.high > 0) {
    const highs = findings.filter(f => f.risk === "high");
    const impact = riskCounts.high * 10;
    factors.push({
      factor: "High-risk functions found",
      impact,
      detail: highs.map(h => h.name).join(", "),
    });
    score += impact;
  }

  // 3. Check for delegatecall / selfdestruct
  const opcodeAnalysis = analyzeOpcodes(code);
  if (opcodeAnalysis.hasDelegatecall) {
    factors.push({ factor: "DELEGATECALL detected", impact: 15, detail: "Contract may execute external code" });
    score += 15;
  }
  if (opcodeAnalysis.hasSelfDestruct) {
    factors.push({ factor: "SELFDESTRUCT detected", impact: 25, detail: "Contract can be destroyed, funds lost" });
    score += 25;
  }

  // 4. Check liquidity
  const liq = await findLiquidityPair(tokenAddress);
  if (!liq.hasLiquidity) {
    factors.push({ factor: "No liquidity", impact: 20, detail: "No V2 liquidity pair found" });
    score += 20;
  } else {
    const wethReserve = Number(ethers.formatEther(liq.reserveWETH));
    if (wethReserve < 0.1) {
      factors.push({ factor: "Very low liquidity", impact: 15, detail: `Only ${wethReserve.toFixed(4)} WETH in pool` });
      score += 15;
    } else if (wethReserve < 1) {
      factors.push({ factor: "Low liquidity", impact: 5, detail: `${wethReserve.toFixed(4)} WETH in pool` });
      score += 5;
    }
  }

  // 5. Check honeypot
  const honeypot = await simulateHoneypot(tokenAddress);
  if (honeypot.isHoneypot) {
    factors.push({ factor: "Honeypot detected", impact: 30, detail: honeypot.details });
    score += 30;
  } else if (honeypot.buyTax !== null && honeypot.sellTax !== null && (honeypot.buyTax + honeypot.sellTax) > 10) {
    factors.push({ factor: "High combined tax", impact: 10, detail: `Buy: ~${honeypot.buyTax}%, Sell: ~${honeypot.sellTax}%` });
    score += 10;
  }

  // 6. Contract size check
  const byteSize = (code.length - 2) / 2;
  if (byteSize < 500) {
    factors.push({ factor: "Very small contract", impact: 10, detail: `Only ${byteSize} bytes — may be minimal proxy or scam` });
    score += 10;
  }

  return { score: Math.min(100, score), factors };
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "base-security-scanner",
  version: "1.0.0",
});

// Tool 1: scan_contract
server.tool(
  "scan_contract",
  "Analyze a smart contract on Base mainnet for security issues including reentrancy patterns, access control, hidden mints, proxy patterns, and dangerous opcodes.",
  {
    address: z.string().describe("Contract address on Base mainnet"),
  },
  async ({ address }) => {
    try {
      const code = await getContractBytecode(address);
      if (code === "0x" || code.length <= 2) {
        return ok({ address, isContract: false, message: "Address is not a contract (EOA or empty)" });
      }

      const selectors = extractSelectors(code);
      const { findings, riskCounts } = analyzeSelectorRisks(selectors);
      const opcodes = analyzeOpcodes(code);
      const contractTypes = identifyContractType(selectors);
      const ownership = await checkOwnership(address);

      const issues: Array<{ severity: string; issue: string; detail: string }> = [];

      // Reentrancy risk: delegatecall + external calls
      if (opcodes.hasDelegatecall) {
        issues.push({ severity: "high", issue: "DELEGATECALL present", detail: "Contract uses delegatecall which can execute arbitrary external code. Potential reentrancy or logic manipulation risk." });
      }

      // Selfdestruct
      if (opcodes.hasSelfDestruct) {
        issues.push({ severity: "critical", issue: "SELFDESTRUCT present", detail: "Contract can be destroyed. All funds and state will be lost permanently." });
      }

      // Access control issues
      if (ownership.hasOwner && !ownership.isRenounced) {
        const dangerousWithOwner = findings.filter(f => f.risk === "critical" || f.risk === "high");
        if (dangerousWithOwner.length > 0) {
          issues.push({
            severity: "high",
            issue: "Active owner with dangerous permissions",
            detail: `Owner (${ownership.owner}) can call: ${dangerousWithOwner.map(f => f.name).join(", ")}`,
          });
        }
      }

      // Hidden mint
      const hasMint = findings.some(f => f.selector === "40c10f19");
      if (hasMint) {
        issues.push({ severity: "critical", issue: "Mint function detected", detail: "Owner can mint unlimited tokens, diluting holders." });
      }

      // Proxy patterns
      const isProxy = contractTypes.includes("Proxy Contract");
      if (isProxy) {
        issues.push({ severity: "medium", issue: "Proxy contract", detail: "Contract logic can be upgraded. The code you see today may change tomorrow." });
      }

      // Token approval traps: check if there's approve but unusual patterns
      const hasApprove = findings.some(f => f.selector === "095ea7b3");
      const hasTransferFrom = findings.some(f => f.selector === "23b872dd");
      if (hasApprove && !hasTransferFrom) {
        issues.push({ severity: "medium", issue: "Approve without transferFrom", detail: "Contract has approve() but no transferFrom(). Unusual pattern — may trap approvals." });
      }

      // Trading control
      const hasTradingControl = findings.some(f => f.selector === "1a8145bb");
      if (hasTradingControl) {
        issues.push({ severity: "critical", issue: "Trading can be disabled", detail: "Owner can call setTradingActive(false) to prevent all trading." });
      }

      return ok({
        address,
        contractTypes,
        bytecodeSize: (code.length - 2) / 2,
        ownership: serializeBigInts(ownership) as Record<string, unknown>,
        opcodeAnalysis: opcodes,
        riskCounts,
        issues,
        knownFunctions: findings,
        totalSelectorsFound: selectors.length,
      });
    } catch (err) {
      return fail(`scan_contract failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// Tool 2: check_honeypot
server.tool(
  "check_honeypot",
  "Check if a token on Base mainnet is a honeypot by simulating buy and sell via Uniswap V2 router. Returns buy/sell ability and estimated taxes.",
  {
    token_address: z.string().describe("Token contract address on Base mainnet"),
  },
  async ({ token_address }) => {
    try {
      const metadata = await getTokenMetadata(token_address);
      const result = await simulateHoneypot(token_address);

      return ok({
        token: token_address,
        metadata: metadata ? serializeBigInts(metadata) as Record<string, unknown> : null,
        honeypotCheck: result,
      });
    } catch (err) {
      return fail(`check_honeypot failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// Tool 3: detect_rug_risk
server.tool(
  "detect_rug_risk",
  "Score rug pull risk 0-100 for a token on Base mainnet. Checks ownership, liquidity, dangerous functions, honeypot status, and contract patterns.",
  {
    token_address: z.string().describe("Token contract address on Base mainnet"),
  },
  async ({ token_address }) => {
    try {
      const metadata = await getTokenMetadata(token_address);
      const rugResult = await computeRugScore(token_address);

      let riskLevel = "low";
      if (rugResult.score >= 70) riskLevel = "critical";
      else if (rugResult.score >= 50) riskLevel = "high";
      else if (rugResult.score >= 30) riskLevel = "medium";

      return ok({
        token: token_address,
        metadata: metadata ? serializeBigInts(metadata) as Record<string, unknown> : null,
        rugScore: rugResult.score,
        riskLevel,
        factors: rugResult.factors,
      });
    } catch (err) {
      return fail(`detect_rug_risk failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// Tool 4: analyze_bytecode
server.tool(
  "analyze_bytecode",
  "Disassemble contract bytecode on Base mainnet and identify known patterns (proxy, diamond, AMM, lending, ERC-20, ERC-721, etc).",
  {
    address: z.string().describe("Contract address on Base mainnet"),
  },
  async ({ address }) => {
    try {
      const code = await getContractBytecode(address);
      if (code === "0x" || code.length <= 2) {
        return ok({ address, isContract: false, message: "Not a contract" });
      }

      const selectors = extractSelectors(code);
      const opcodes = analyzeOpcodes(code);
      const contractTypes = identifyContractType(selectors);

      // Map known selectors
      const knownFunctions: Array<{ selector: string; name: string; category: string }> = [];
      for (const sel of selectors) {
        if (KNOWN_SELECTORS[sel]) {
          knownFunctions.push({ selector: sel, name: KNOWN_SELECTORS[sel].name, category: KNOWN_SELECTORS[sel].risk });
        } else if (PATTERN_SELECTORS[sel]) {
          knownFunctions.push({ selector: sel, name: PATTERN_SELECTORS[sel], category: "pattern" });
        }
      }

      // Unknown selectors
      const unknownSelectors = selectors.filter(
        s => !KNOWN_SELECTORS[s] && !PATTERN_SELECTORS[s]
      );

      return ok({
        address,
        bytecodeSize: (code.length - 2) / 2,
        contractTypes,
        opcodeAnalysis: opcodes,
        knownFunctions,
        unknownSelectors: unknownSelectors.slice(0, 50), // cap output
        totalSelectors: selectors.length,
        knownCount: knownFunctions.length,
        unknownCount: unknownSelectors.length,
      });
    } catch (err) {
      return fail(`analyze_bytecode failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// Tool 5: check_token_permissions
server.tool(
  "check_token_permissions",
  "Check owner permissions on a token: can mint? can pause? can blacklist? can change fees? Can disable trading? Ownership renounced?",
  {
    token_address: z.string().describe("Token contract address on Base mainnet"),
  },
  async ({ token_address }) => {
    try {
      const code = await getContractBytecode(token_address);
      if (code === "0x" || code.length <= 2) {
        return ok({ token: token_address, isContract: false, message: "Not a contract" });
      }

      const selectors = extractSelectors(code);
      const ownership = await checkOwnership(token_address);

      const permissions: Record<string, { present: boolean; risk: string; detail: string }> = {
        canMint: {
          present: selectors.includes("40c10f19"),
          risk: "critical",
          detail: "mint(address,uint256) -- can create new tokens",
        },
        canPause: {
          present: selectors.includes("8456cb59"),
          risk: "high",
          detail: "pause() -- can freeze all transfers",
        },
        canBlacklist: {
          present: selectors.includes("44337ea1"),
          risk: "high",
          detail: "blacklist(address) -- can block specific addresses",
        },
        canChangeFees: {
          present: selectors.includes("69fe0e2d"),
          risk: "high",
          detail: "setFee(uint256) -- can change transaction fees",
        },
        canDisableTrading: {
          present: selectors.includes("1a8145bb"),
          risk: "critical",
          detail: "setTradingActive(bool) -- can disable all trading",
        },
        canSetMaxTx: {
          present: selectors.includes("e4748b9e"),
          risk: "high",
          detail: "setMaxTxAmount(uint256) -- can restrict transaction sizes",
        },
        canSetMaxWallet: {
          present: selectors.includes("8ee88c53"),
          risk: "high",
          detail: "setMaxWalletSize(uint256) -- can restrict wallet holdings",
        },
        canBurnOthers: {
          present: selectors.includes("79cc6790"),
          risk: "medium",
          detail: "burnFrom(address,uint256) -- can burn tokens from other addresses",
        },
        canUpgrade: {
          present: selectors.includes("3659cfe6") || selectors.includes("4f1ef286"),
          risk: "critical",
          detail: "upgradeTo/upgradeToAndCall -- proxy can be upgraded to new logic",
        },
        canRenounceOwnership: {
          present: selectors.includes("715018a6"),
          risk: "info",
          detail: "renounceOwnership() -- ownership can be given up (positive sign)",
        },
        canTransferOwnership: {
          present: selectors.includes("f2fde38b"),
          risk: "medium",
          detail: "transferOwnership(address) -- ownership can be moved to another address",
        },
      };

      const dangerousPermissions = Object.entries(permissions)
        .filter(([, v]) => v.present && (v.risk === "critical" || v.risk === "high"))
        .map(([k]) => k);

      return ok({
        token: token_address,
        ownership: serializeBigInts(ownership) as Record<string, unknown>,
        permissions,
        dangerousPermissions,
        riskSummary: dangerousPermissions.length === 0
          ? "No dangerous owner permissions detected"
          : `${dangerousPermissions.length} dangerous permission(s) found: ${dangerousPermissions.join(", ")}`,
      });
    } catch (err) {
      return fail(`check_token_permissions failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// Tool 6: get_contract_info
server.tool(
  "get_contract_info",
  "Get basic contract metadata on Base mainnet: is it a contract, bytecode size, ETH balance, transaction count. For tokens, also returns name/symbol/supply.",
  {
    address: z.string().describe("Contract or EOA address on Base mainnet"),
  },
  async ({ address }) => {
    try {
      const info = await getBasicContractInfo(address);

      let tokenInfo: Record<string, unknown> | null = null;
      if (info.isContract) {
        tokenInfo = await getTokenMetadata(address);
        if (tokenInfo) {
          tokenInfo = serializeBigInts(tokenInfo) as Record<string, unknown>;
        }
      }

      return ok({
        ...info,
        tokenMetadata: tokenInfo,
      });
    } catch (err) {
      return fail(`get_contract_info failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// Tool 7: compare_bytecode
server.tool(
  "compare_bytecode",
  "Compare bytecode of two contracts on Base mainnet for clone detection. Returns similarity score and whether they share the same code.",
  {
    address1: z.string().describe("First contract address"),
    address2: z.string().describe("Second contract address"),
  },
  async ({ address1, address2 }) => {
    try {
      const [code1, code2] = await Promise.all([
        getContractBytecode(address1),
        getContractBytecode(address2),
      ]);

      const isContract1 = code1 !== "0x" && code1.length > 2;
      const isContract2 = code2 !== "0x" && code2.length > 2;

      if (!isContract1 || !isContract2) {
        return ok({
          address1,
          address2,
          isContract1,
          isContract2,
          match: false,
          similarity: 0,
          message: "One or both addresses are not contracts",
        });
      }

      const exactMatch = code1 === code2;

      // Calculate similarity: compare bytecode chunks
      let similarity = 0;
      if (exactMatch) {
        similarity = 100;
      } else {
        // Compare selectors as a proxy for functional similarity
        const sel1 = new Set(extractSelectors(code1));
        const sel2 = new Set(extractSelectors(code2));
        const intersection = new Set([...sel1].filter(s => sel2.has(s)));
        const union = new Set([...sel1, ...sel2]);
        similarity = union.size > 0 ? Math.round((intersection.size / union.size) * 100) : 0;
      }

      const types1 = identifyContractType(extractSelectors(code1));
      const types2 = identifyContractType(extractSelectors(code2));

      return ok({
        address1,
        address2,
        bytecodeSize1: (code1.length - 2) / 2,
        bytecodeSize2: (code2.length - 2) / 2,
        exactMatch,
        selectorSimilarity: similarity,
        contractTypes1: types1,
        contractTypes2: types2,
        verdict: exactMatch
          ? "Exact clone — identical bytecode"
          : similarity > 80
          ? "Very similar — likely forked from same source"
          : similarity > 50
          ? "Moderately similar — may share common patterns"
          : "Different contracts",
      });
    } catch (err) {
      return fail(`compare_bytecode failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// Tool 8: audit_report
server.tool(
  "audit_report",
  "Generate a full security audit report for a token on Base mainnet. Combines contract scan, honeypot check, rug risk score, bytecode analysis, and permission checks into one comprehensive report.",
  {
    token_address: z.string().describe("Token contract address on Base mainnet"),
  },
  async ({ token_address }) => {
    try {
      const code = await getContractBytecode(token_address);
      if (code === "0x" || code.length <= 2) {
        return ok({
          token: token_address,
          isContract: false,
          report: "Address is not a contract. Cannot generate audit report.",
        });
      }

      // Run all checks in parallel
      const [
        contractInfo,
        tokenMeta,
        ownership,
        honeypot,
        rugResult,
        liquidity,
      ] = await Promise.all([
        getBasicContractInfo(token_address),
        getTokenMetadata(token_address),
        checkOwnership(token_address),
        simulateHoneypot(token_address),
        computeRugScore(token_address),
        findLiquidityPair(token_address),
      ]);

      const selectors = extractSelectors(code);
      const { findings, riskCounts } = analyzeSelectorRisks(selectors);
      const opcodes = analyzeOpcodes(code);
      const contractTypes = identifyContractType(selectors);

      // Permission summary
      const dangerousSelectors = findings.filter(f => f.risk === "critical" || f.risk === "high");
      const permissionSummary = dangerousSelectors.length === 0
        ? "No dangerous owner permissions detected"
        : `${dangerousSelectors.length} dangerous permission(s): ${dangerousSelectors.map(f => f.name).join(", ")}`;

      // Overall risk
      let overallRisk = "LOW";
      if (rugResult.score >= 70 || honeypot.isHoneypot) overallRisk = "CRITICAL";
      else if (rugResult.score >= 50) overallRisk = "HIGH";
      else if (rugResult.score >= 30) overallRisk = "MEDIUM";

      // Build recommendations
      const recommendations: string[] = [];
      if (ownership.hasOwner && !ownership.isRenounced) {
        recommendations.push("Request ownership renouncement or verify owner identity");
      }
      if (honeypot.isHoneypot) {
        recommendations.push("DO NOT BUY — honeypot detected");
      }
      if (riskCounts.critical > 0) {
        recommendations.push("Critical functions detected — review contract source code on Basescan");
      }
      if (opcodes.hasSelfDestruct) {
        recommendations.push("SELFDESTRUCT present — contract can be destroyed at any time");
      }
      if (opcodes.hasDelegatecall) {
        recommendations.push("DELEGATECALL present — verify proxy implementation is safe");
      }
      if (!liquidity.hasLiquidity) {
        recommendations.push("No liquidity found — cannot trade this token");
      }
      if (recommendations.length === 0) {
        recommendations.push("No major red flags found. Always DYOR and start with small positions.");
      }

      return ok(serializeBigInts({
        report: "BASE SECURITY SCANNER - AUDIT REPORT",
        token: token_address,
        timestamp: new Date().toISOString(),
        overallRisk,
        rugScore: rugResult.score,
        tokenMetadata: tokenMeta,
        contractInfo: {
          bytecodeSize: contractInfo.bytecodeSize,
          balanceETH: contractInfo.balanceETH,
          contractTypes,
          complexity: opcodes.estimatedComplexity,
        },
        ownership: {
          hasOwner: ownership.hasOwner,
          owner: ownership.owner,
          isRenounced: ownership.isRenounced,
        },
        honeypotAnalysis: {
          isHoneypot: honeypot.isHoneypot,
          canBuy: honeypot.canBuy,
          canSell: honeypot.canSell,
          estimatedBuyTax: honeypot.buyTax,
          estimatedSellTax: honeypot.sellTax,
          details: honeypot.details,
        },
        liquidity: {
          pairAddress: liquidity.pairAddress,
          hasLiquidity: liquidity.hasLiquidity,
          reserveWETH: liquidity.reserveWETH,
        },
        dangerousOpcodes: {
          delegatecall: opcodes.hasDelegatecall,
          selfdestruct: opcodes.hasSelfDestruct,
          create: opcodes.hasCreate,
          create2: opcodes.hasCreate2,
        },
        permissionSummary,
        riskCounts,
        rugFactors: rugResult.factors,
        recommendations,
        knownFunctions: findings,
      }) as Record<string, unknown>);
    } catch (err) {
      return fail(`audit_report failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
