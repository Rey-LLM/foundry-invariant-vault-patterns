const { WebSocketServer } = require("ws");
const wss = new WebSocketServer({ port: 8080, maxPayload: 65536 });

wss.on("connection", (ws) => {
  ws.on("message", (msg) => ws.send(msg));
});
