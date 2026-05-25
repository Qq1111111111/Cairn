# Task
You will receive a YAML snapshot of the task graph. In the YAML graph, facts represent key objective facts, and intents represent exploration intents. The graph always moves from one or more facts to a new fact by proposing an intent for exploration. You need to interpret the graph information, understand the overall situation and progress, then become an expert in this domain.
But note that you are not continuing the task here, and you do not need to wait for unfinished tasks or commands. You only need to summarize the key facts that have already been confirmed so far and are most helpful for reaching Goal.
This is the conclude phase. It overrides any earlier instruction in the same session that told you to keep working, continue exploring, solve Goal, wait for command results, or perform more actions.

# Output Requirements
Return only one raw JSON object. Do not output anything else. The JSON must be valid, including proper escaping of quotation marks.

When rejecting a task, return the following:
```json
{"accepted": false, "reason": "policy_refusal"}
```

Normal return example:
```json
{"accepted": true, "data": {"description": "..."}}
```

If the confirmed result contains one or more security findings, you must add a sidecar `report`.
This report is stored only for UI/reporting and is not inserted back into the graph context:
```json
{
  "accepted": true,
  "data": {
    "description": "short objective fact for the graph",
    "report": {
      "title": "漏洞报告",
      "summary": "brief report summary",
      "findings": [
        {
          "title": "finding title",
          "asset": "affected asset",
          "endpoint": "method and path, if any",
          "type": "vulnerability type",
          "status": "已确认",
          "severity": "高危",
          "finding": "what was confirmed",
          "fix": "recommended remediation",
          "evidence": [
            {
              "kind": "packet",
              "label": "请求包",
              "request_packet": "raw request packet",
              "response_packet": "raw response packet"
            },
            {
              "kind": "code",
              "label": "代码原文",
              "content": "raw code block or endpoint list"
            }
          ]
        }
      ]
    }
  }
}
```

# Rules
- Stop immediately and produce the JSON now. Do not continue the task.
- Do not run any more commands, make any more tool calls, inspect anything else, wait for any unfinished command, or try to obtain any additional information.
- Base your answer only on information that has already been confirmed before this conclude prompt. If something has not already been confirmed, do not wait for it and do not include it.
- This JSON summary is your final output for this phase. After outputting it, stop.
- `description` must be an already confirmed objective factual conclusion. Do not output plans, guesses, or explanatory filler. Do not put long data blobs in `description`; long data should be placed in a file and referenced from `description` instead. When multiple confirmed points exist, separate them with line breaks or short paragraphs instead of one dense paragraph.
- `description` should contain only the latest incremental facts discovered. Do not repeat information already present in the graph snapshot, and do not include redundant details that do not help advance Goal.
- Include `report` whenever the current result confirms at least one security finding. If the current result is only a tentative guess, an unverified suspicion, or confirms no security issue, omit `report` entirely.
- Put every distinct vulnerability in `report.findings`.
- Use packet evidence only for findings that are proven by HTTP request/response behavior. For file/code/config leaks, use `kind: "code"` and place the surrounding source code, leaked endpoint list, or other raw excerpt in `content`. Do not force non-web issues into request/response packets.

# Context
## Graph
```
{graph_yaml}
```

## Current Intent
```
{intent_id}
```

## Current Intent Description
```
{intent_description}
```
