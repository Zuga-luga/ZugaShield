# Approval Provider (Human-in-the-Loop)

ZugaShield supports a Human-in-the-Loop (HIL) pattern for actions that require human review before proceeding. Implement `ApprovalProvider` to connect ZugaShield to any approval system: Slack, Discord, a web UI, a CLI prompt, etc.

## Abstract Base Class

```python
from zugashield.integrations.approval import ApprovalProvider
from zugashield.types import ShieldDecision

class ApprovalProvider(ABC):
    @abstractmethod
    async def request_approval(
        self,
        decision: ShieldDecision,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Request human approval for a challenged action.

        Args:
            decision: The ShieldDecision with verdict=CHALLENGE
            context:  Additional context (tool name, session ID, etc.)

        Returns:
            True if approved, False if denied
        """
        ...

    async def notify(
        self,
        decision: ShieldDecision,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Notify about a security event (no approval needed).
        Override to send alerts for BLOCK/QUARANTINE events.
        Default implementation is a no-op.
        """
        pass
```

## Register a Provider

```python
from zugashield import ZugaShield, set_approval_provider

shield = ZugaShield()
set_approval_provider(MyApprovalProvider())
```

Retrieve the current provider:

```python
from zugashield import get_approval_provider

provider = get_approval_provider()
```

## NoOpApprovalProvider

The built-in default. Auto-denies all `request_approval` calls. Used when no provider is registered.

```python
from zugashield.integrations.approval import NoOpApprovalProvider

# Equivalent to: no provider registered
set_approval_provider(NoOpApprovalProvider())
```

## Slack Example

```python
import httpx
from zugashield.integrations.approval import ApprovalProvider
from zugashield.types import ShieldDecision

class SlackApproval(ApprovalProvider):
    def __init__(self, webhook_url: str, approval_endpoint: str):
        self.webhook_url = webhook_url
        self.approval_endpoint = approval_endpoint

    async def request_approval(
        self,
        decision: ShieldDecision,
        context=None,
    ) -> bool:
        threat = (
            decision.threats_detected[0] if decision.threats_detected else None
        )
        message = {
            "text": (
                f"*ZugaShield Approval Required*\n"
                f"Layer: `{decision.layer}`\n"
                f"Threat: {threat.description if threat else 'Unknown'}\n"
                f"Evidence: `{threat.evidence[:100] if threat else ''}`\n"
                f"Approve? Reply with `yes` or `no`."
            )
        }
        async with httpx.AsyncClient() as client:
            await client.post(self.webhook_url, json=message)

        # Wait for human response via your approval_endpoint
        # (polling, webhook callback, etc.)
        response = await self._wait_for_response()
        return response == "yes"

    async def notify(self, decision, context=None):
        # Send non-interactive alert for BLOCK events
        threat = (
            decision.threats_detected[0] if decision.threats_detected else None
        )
        async with httpx.AsyncClient() as client:
            await client.post(self.webhook_url, json={
                "text": (
                    f":warning: *ZugaShield BLOCKED*: "
                    f"{threat.description if threat else 'Unknown threat'}"
                )
            })

    async def _wait_for_response(self) -> str:
        # Implement your response collection mechanism
        ...
```

Register it:

```python
from zugashield import ZugaShield, set_approval_provider

shield = ZugaShield()
set_approval_provider(SlackApproval(
    webhook_url="https://hooks.slack.com/services/...",
    approval_endpoint="https://yourapp.com/approvals",
))
```

## When Is Approval Requested?

`request_approval` is called by your application code when `decision.requires_approval` is True (verdict is `CHALLENGE`). ZugaShield does not call it automatically — you control the integration point.

```python
decision = await shield.check_tool_call("send_email", params)

if decision.requires_approval:
    provider = get_approval_provider()
    approved = await provider.request_approval(decision, context={"tool": "send_email"})
    if not approved:
        raise PermissionError("Tool call denied by human reviewer")
elif decision.is_blocked:
    raise SecurityError(f"Blocked: {decision.verdict}")
```

Last Updated: 2026-02-17
