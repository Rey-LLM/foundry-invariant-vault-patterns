const { WebSocketServer } = require("ws");
const server = require("./server");

const wss = new WebSocketServer({ server, maxPayload: 65536 });
