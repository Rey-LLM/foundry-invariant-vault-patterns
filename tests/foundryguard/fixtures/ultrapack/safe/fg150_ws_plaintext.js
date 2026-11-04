const socket = new WebSocket("wss://api.example.com/stream");
socket.onmessage = (e) => render(JSON.parse(e.data));
