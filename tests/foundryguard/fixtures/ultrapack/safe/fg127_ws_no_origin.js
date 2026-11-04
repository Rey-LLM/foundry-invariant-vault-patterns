const { WebSocketServer } = require("ws");
const server = require("./server");
const ALLOWED = new Set(["https://app.example.com"]);

const wss = new WebSocketServer({ server, maxPayload: 65536, verifyClient: (info) => ALLOWED.has(info.origin) });
