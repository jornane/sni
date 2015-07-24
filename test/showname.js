var sni = require("sni")
  , net = require("net");

net.createServer(function(socket) {
	socket.once("data", function(data) {
		console.log(sni(data));
    });
}).listen(2443);
