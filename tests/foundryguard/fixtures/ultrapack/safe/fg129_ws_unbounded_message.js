const { WebSocketServer } = require("ws");
const wss = new WebSocketServer({ port: 8080, maxPayload: 64 * 1024 });
