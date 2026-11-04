const { WebSocketServer } = require("ws");
const { verifyToken } = require("./auth");
const wss = new WebSocketServer({ port: 8080, maxPayload: 65536 });

wss.on("connection", (ws, req) => {
  const user = verifyToken(new URL(req.url, "https://x").searchParams.get("t"));
  if (!user) return ws.close(1008);
  ws.on("message", (msg) => ws.send(msg));
});
