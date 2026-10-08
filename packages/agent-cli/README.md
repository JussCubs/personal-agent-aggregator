# @agent-aggregator/agent-cli

`agg`, the deterministic agent-side CLI for the personal agent aggregator.
Every routine step is a command with a documented exit code, so cron jobs and
hooks can run it without waking a language model.

```sh
agg setup --claim XXXXX-XXXXX-XXXXX-XXXXX --server https://aggregator.example.com/api
agg doctor
agg ask --id q-1 --prompt "Proceed?" --option yes=Yes --option no=No
agg install-poller --every-minutes 1 --exec '<command that wakes your agent>'
agg answer --id q-1 && agg ack --id q-1 --revision 1
```

Exit codes: 0 ok or something new, 1 error, 2 usage, 3 nothing new or still
pending, 4 credential missing or invalid, 5 question closed without an answer.
Configuration: `AGG_URL`, `AGG_TOKEN`, or `${XDG_CONFIG_HOME:-~/.config}/agent-aggregator/hub.json`.
Full command reference: [docs/contract.md](../../docs/contract.md#clis); setup:
[connect a polling agent](../../docs/playbooks/connect-polling-agent.md). License: Apache-2.0.
