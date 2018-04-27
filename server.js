let NodeRSA = require('node-rsa');
let net=require("net");
let readline = require('readline');
let port = process.argv[2];
let username =  process.argv[3] || 'Anonymous'
let socket;
let client;

let rl = readline.createInterface(process.stdin, process.stdout);
let serverRSA  = new NodeRSA({b: 512});
let clientRSA = new NodeRSA({b: 512});
net.createServer(function(socket){
    socket.name = socket.remoteAddress;
    console.log(socket.name+' connected');
    socket.setEncoding('utf8');
    client = socket;
	console.log(`Connected to ${client.name}`);
    socket.on("data",function(data){	
		 //если нам прислали публичный ключ, записываем его и посылаем свой. 
		 if(isPuplicKey(data)) {
			console.log("client public key:");
			console.log(data.toString());
			clientRSA.importKey(data, 'pkcs8-public');
			socket.write(serverRSA.exportKey('public'));	
		 }
		 else {
			 console.log(serverRSA.decrypt(data, 'utf8'))
		 }
    });

    socket.on("close",function(){
        console.log(socket.name + " has disconnected");
    })

}).listen(port);

function sendMsg(msg){
	
    client.write(clientRSA.encrypt(msg, 'base64'));
}

rl.on('line', function (line) {
	 sendMsg(username+": "+line); 
});

//Пока такой тупой сопосб проверить что переданное значение явлется ключем
function isPuplicKey (key) {
	if(key.indexOf("BEGIN PUBLIC KEY-----")>0) {
		return true;
	} else return false;
}