const socket = new WebSocket("ws://api.example.com/stream");
socket.onmessage = (e) => render(JSON.parse(e.data));
