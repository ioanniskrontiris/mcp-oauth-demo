// agent/src/main.js
import { StateGraph } from "@langchain/langgraph";
import { z } from "zod";
import { MCPClient } from "./mcpClient.js";

// 1) Define graph state with Zod (recommended)
const State = z.object({
  goal: z.string(),
  sessionReady: z.boolean().default(false),
  lastEcho: z.string().optional(),
});

// 2) Our tiny MCP client wrapper (talks to the gateway)
const client = new MCPClient();

// 3) Build the LangGraph
const graph = new StateGraph(State)
  .addNode("ensureSession", async (state) => {
    await client.ensureSession();
    return { sessionReady: true };
  })
  .addNode("echo", async (state) => {
    const r = await client.tools.echo({ msg: "hello" });
    return { lastEcho: r.echo ?? "(no echo)" };
  })
  .addEdge("__start__", "ensureSession")
  .addEdge("ensureSession", "echo");

// 4) Compile and run once
const app = graph.compile();

async function run() {
  const result = await app.invoke({
    goal: "Call the MCP echo via gateway",
  });

  console.log("\n--- Agent result ---");
  console.log({
    goal: result.goal,
    sessionReady: result.sessionReady,
    lastEcho: result.lastEcho,
  });
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});