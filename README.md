# AgentPay State Channel Dispute Resolution PoC

## Vulnerability Summary

A critical vulnerability exists in Celer AgentPay's state channel dispute resolution mechanism. The payment finalization step has a 12-second frontrunning window that allows an attacker to steal channel funds during dispute resolution.

## Impact
- **Severity**: Critical (CVSS 9.1)
- **Type**: Race Condition / Frontrunning
- **Affected**: AgentPay state channel payment finalization
- **Vector**: On-chain transaction ordering manipulation

## Reproduction

```bash
go run main.go --rpc https://eth.llamarpc.com --contract <AGENTPAY_CONTRACT>
```

## Responsible Disclosure

This PoC is shared for responsible disclosure purposes. Please do not use for malicious purposes.

## Timeline
- 2026-04-15: Vulnerability discovered during code review
- 2026-04-18: PoC developed and verified
- 2026-04-18: Initial disclosure to Celer team
