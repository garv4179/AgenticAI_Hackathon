# 2-4 Minute Demo Script

## 0:00-0:20 - Problem
"Our AI agents increasingly read user messages, emails, web pages, PDFs and API responses. An attacker can hide instructions inside that content and trick the agent into overriding policy, leaking secrets or abusing tools."

## 0:20-0:45 - Solution
"We built an Agentic Prompt Injection Firewall. It sits in front of the AI agent and autonomously performs intake, detection, risk analysis, sanitization, tool guarding, validation and audit logging."

## 0:45-1:15 - Safe traffic
Paste a normal telecom support request. Click Inspect. Show ALLOW and the clean payload.

## 1:15-1:50 - Direct prompt injection
Load the demo attack. Show Instruction Override + Secret Extraction + Tool Abuse. The policy agent selects a high-risk action and the Tool Guard blocks execution.

## 1:50-2:25 - Indirect injection
Change source to PDF or web page and paste the retrieved-content attack. Show that external-source risk raises the containment level and the payload is quarantined.

## 2:25-2:50 - Encoded attack
Paste the base64 scenario. Show Encoded Instructions detection and the decoded evidence in the trace.

## 2:50-3:20 - Agentic autonomy
Open Agent Trace. Explain that no human approval is required in the prototype loop: the system detects, decides, contains and validates automatically. High-risk content fails closed.

## 3:20-3:40 - Close
"The result is a reusable security layer for agentic systems: legitimate content passes with minimal disruption, while risky content is neutralized before it can influence downstream reasoning or tool execution."
