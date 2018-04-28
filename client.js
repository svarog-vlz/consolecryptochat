const net=require("net");
const NodeRSA = require('node-rsa');
const readline = require('readline');
let client= new net.Socket();
const rl = readline.createInterface(process.stdin, process.stdout);

const port = process.argv[2];
const host = process.argv[3] || 'localhost';
const username =  process.argv[4] || 'Anonymous'


let serverRSA  = new NodeRSA({b: 512});
let clientRSA  = new NodeRSA({b: 512});


client.connect(port, host, function(){
    client.name = client.remoteAddress;
	console.log(`Connected to ${client.name}`);
	client.write(clientRSA.exportKey('public'))
});


client.on("data",function(data){
	if(isPuplicKey(data)) {
			console.log("server public key:");	
			serverRSA.importKey(data,'pkcs8-public');
			console.log(data.toString());
		 } else {

		 	message = JSON.parse(data);
		 	msg = clientRSA.decrypt(message.msg, 'utf8');
		 	if(serverRSA.verify(msg.toString(), message.sign.toString(), 'utf8', 'base64')) {
		 		console.log(msg);
		 	} else console.log("NOT VERYFED:"+msg);
		 }
			 
		
    
})


function sendMsg(msg){

	let sign = clientRSA.sign(msg, 'base64');
	let mes =  {
		msg: serverRSA.encrypt(msg, 'base64'),
		sign: sign
	}
    client.write(JSON.stringify(mes));
}

rl.on('line', function (line) {
    sendMsg(username+": "+line);  
});


function isPuplicKey (key) {
	if(key.indexOf("BEGIN PUBLIC KEY-----")>0) {
		return true;
	} else return false;
}