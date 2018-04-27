let net=require("net");
var NodeRSA = require('node-rsa');
let readline = require('readline');
let client=new net.Socket();
let rl = readline.createInterface(process.stdin, process.stdout);

let port = process.argv[3];
let host = process.argv[2];
let username =  process.argv[4] || 'Anonymous'

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
			 console.log(clientRSA.decrypt(data.toString(), 'utf8')); 
		 }
			 
		
    
})


function sendMsg(msg){
    client.write(serverRSA.encrypt(msg, 'base64'));
}

rl.on('line', function (line) {
    sendMsg(username+": "+line);  
});

function isPuplicKey (key) {
	if(key.indexOf("BEGIN PUBLIC KEY-----")>0) {
		return true;
	} else return false;
}