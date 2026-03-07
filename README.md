# base-security-scanner-mcp

MCP server for AI agents to scan smart contracts on Base mainnet for security vulnerabilities. Detect honeypots, rug pulls, hidden mints, proxy patterns, and generate full audit reports -- all read-only, no private key needed.

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

## License

MIT
