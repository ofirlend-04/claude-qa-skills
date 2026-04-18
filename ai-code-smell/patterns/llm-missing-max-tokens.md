# LLM Call Without `max_tokens`

**Severity:** P1
**Real evidence:**
- HN / Reddit 2025–2026: Cursor users hit with $1,400+ bills from runaway outputs.
- [Anthropic API reference](https://docs.anthropic.com/claude/reference/messages_post) — `max_tokens` is REQUIRED, not optional.
- [OpenAI Chat Completions](https://platform.openai.com/docs/api-reference/chat) — `max_tokens` defaults to "infinite" (up to model context).

## Bug

```ts
const res = await client.messages.create({
  model: "claude-opus-4-7",
  messages: [{ role: "user", content: userInput }],
  // max_tokens missing!
});
```

On Anthropic's SDK this will fail at runtime (it's required). On OpenAI's SDK it will run and potentially emit 4096+ tokens per call. If your agent loops (retry on error, tool-calling, autonomous mode) you can burn hundreds of dollars in minutes.

## Fix

Always cap output:

```ts
const res = await client.messages.create({
  model: "claude-opus-4-7",
  max_tokens: 1024,          // ← always
  messages: [{ role: "user", content: userInput }],
});
```

For long outputs you genuinely need, stream + cut off on a semantic boundary rather than relying on "max context".

## Detection rule

Regex across `.py` / `.ts` / `.js`:

```
(?:client|anthropic|openai)\.(?:messages|chat\.completions)\.create\s*\([^)]*
```

If the matched args block doesn't contain `max_tokens` or `maxTokens`, flag P1.

## False positives

- A wrapper function that forwards kwargs / `...rest`. Scanner sees no `max_tokens` on the literal call. Suppress with `// qa-ignore: L1` — the wrapper's caller is responsible.
- Streaming endpoints (`stream: True`) — you still want `max_tokens` as a hard ceiling, so we keep flagging these.
