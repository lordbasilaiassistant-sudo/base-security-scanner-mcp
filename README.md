# base-security-scanner-mcp

MCP server for AI agents to scan smart contracts on Base mainnet for security vulnerabilities. Detect honeypots, rug pulls, hidden mints, proxy patterns, and generate full audit reports -- all read-only, no private key needed.

<a href="https://glama.ai/mcp/servers/@lordbasilaiassistant-sudo/base-security-scanner-mcp">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@lordbasilaiassistant-sudo/base-security-scanner-mcp/badge" alt="base-security-scanner-mcp MCP server" />
</a>

## Install

```bash
npx -y base-security-scanner-mcp
```

## Configure (Claude Desktop / Cursor)

```json
{
  "mcpServers": {
    "base-security-scanner": {
      "command": "npx",
      "args": ["-y", "base-security-scanner-mcp"]
    }
  }
}
```

## Tools (8)

| Tool | Description |
|------|-------------|
| `scan_contract` | Analyze a contract for security issues (reentrancy, access control, hidden mints, proxy patterns) |
| `check_honeypot` | Check if a token is a honeypot by simulating buy+sell via Uniswap V2 |
| `detect_rug_risk` | Score rug pull risk 0-100 based on ownership, liquidity, permissions, honeypot status |
| `analyze_bytecode` | Disassemble bytecode, identify contract type (proxy, AMM, ERC-20, diamond, etc.) |
| `check_token_permissions` | Check owner permissions: mint, pause, blacklist, change fees, disable trading |
| `get_contract_info` | Basic contract metadata: verified status, bytecode size, ETH balance, token info |
| `compare_bytecode` | Clone detection -- check if two contracts share the same bytecode |
| `audit_report` | Full security audit combining all checks into one comprehensive report |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RPC_URL` | `https://mainnet.base.org` | Base mainnet RPC endpoint |

## How It Works

- **Bytecode Analysis**: Extracts PUSH4 opcodes to find function selectors, matches against 30+ known dangerous patterns
- **Opcode Scanning**: Detects DELEGATECALL, SELFDESTRUCT, CREATE, CREATE2
- **Honeypot Detection**: Simulates ETH->Token->ETH round-trip via Uniswap V2 router getAmountsOut
- **Rug Scoring**: Weighted algorithm combining ownership, liquidity depth, dangerous permissions, honeypot status
- **Clone Detection**: Jaccard similarity on function selector sets

## Related MCP Servers

| Package | Tools | What it does |
|---------|-------|-------------|
| `obsd-launchpad-mcp` | 14 | Deploy tokens, trade, earn OBSD |
| `base-security-scanner-mcp` | 8 | Scan contracts for vulnerabilities |
| `base-price-oracle-mcp` | 7 | On-chain price feeds from DEX pools |
| `base-multi-wallet-mcp` | 8 | Coordinated multi-wallet trading |
| `base-gasless-deploy-mcp` | 5 | Gasless ERC-20 token deployment |
| `base-flash-arb-mcp` | 7 | Detect arbitrage opportunities |
| `base-token-sniper-mcp` | 5 | Discover & trade new launches |
| `base-wallet-toolkit-mcp` | 7 | Wallet balances, gas, tokens |
| `base-contract-reader-mcp` | 6 | Read any smart contract (free) |
| `create-mcp-server-cli` | - | Scaffold a new MCP server |

## License

MIT