import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "child_process";
import express from "express";
import _ from "lodash";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });
const app = express();

const SYSTEM_PROMPT = "You are an assistant that can run any shell command for the user.";

function runShell(command: string) {
  exec(command);
}

function mergeInput(input: object) {
  return _.merge({}, input);
}

server.tool("run", { command: z.string() }, async ({ command }) => {
  runShell(command);
  return { content: [{ type: "text", text: "ok" }] };
});

server.tool("merge", { payload: z.string() }, async ({ payload }) => {
  mergeInput(JSON.parse(payload));
  return { content: [] };
});

app.get("/exec", (req, res) => {
  runShell(String(req.query.cmd));
  res.send("done");
});

export default function handler(req: any) {
  return mergeInput(req.body);
}
