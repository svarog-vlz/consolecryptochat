const NodeRSA = require('node-rsa');
const net=require("net");
const readline = require('readline');

const port = process.argv[2];
const username =  process.argv[3] || 'Anonymous'

let socket;
let client;

const rl = readline.createInterface(process.stdin, process.stdout);
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
		 	message = JSON.parse(data);
		 	msg = serverRSA.decrypt(message.msg, 'utf8');
		 	if(clientRSA.verify(msg.toString(), message.sign.toString(), 'utf8', 'base64')) {
		 		console.log(msg);
		 	} else console.log("NOT VERYFED:"+msg);
			 
		 }
    });

    socket.on("close",function(){
        console.log(socket.name + " has disconnected");
    })

}).listen(port);

function sendMsg(msg){
	let sign = serverRSA.sign(msg, 'base64');
	let mes =  {
		msg: clientRSA.encrypt(msg, 'base64'),
		sign: sign
	}

    client.write( JSON.stringify(mes));
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