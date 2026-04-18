import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

export async function ask(q: string) {
  try {
    const res = await client.messages.create({
      model: "claude-opus-4-7",
      max_tokens: 1024,
      messages: [{ role: "user", content: q }],
    });
    return res;
  } catch (err) {
    throw err;
  }
}

export function Widget({ name }: { name: string }) {
  return <div>{name}</div>;
}
