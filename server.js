const NodeRSA = require('node-rsa');
const net=require("net");
const readline = require('readline');
const color = require('colors');

const port = process.argv[2];
const username =  process.argv[3] || 'Anonymous' // Anonymous - по умолчанию

const rl = readline.createInterface(process.stdin, process.stdout);

let socket;
let client;

console.log ("Server start, and waitng client on "+ color.red(port)+" port")

// Создаем обьекты RSA для себя и сервера
let serverRSA  = new NodeRSA({b: 512});
let clientRSA = new NodeRSA({b: 512});

net.createServer(function(socket){
    console.log(color.red(socket.remoteAddress)+' connected');
    socket.setEncoding('utf8');
    client = socket;
    socket.on("data",function(data){	
		 //Если переданные данные являются публичным ключем 
		 if(isPuplicKey(data)) {
			 //Импортируем клиентский ключ в ранее созданный обьект
			clientRSA.importKey(data, 'pkcs8-public');
			//Отправляем свой публичный ключ клиенту
			socket.write(serverRSA.exportKey('public'));
			console.log(`Encrypted connection established \n`);
		 }
		 else {
		 	message = JSON.parse(data);
			//Расшифровываем собщение своим публичным ключом
		 	msg = serverRSA.decrypt(message.msg, 'utf8');
			//Проверяем цифровую подпись сообщения
		 	if(clientRSA.verify(msg.toString(), message.sign.toString(), 'utf8', 'base64')) {
		 		console.log(color.green(msg));
		 	} else console.log(color.red("NOT VERYFED:"+msg));
			 
		 }
    });

    socket.on("close",function(){
        console.log(socket.remoteAddress + " has disconnected");
    })

}).listen(port);
//Отправка сообщений
function sendMsg(msg){
	//Создаем цифровую подпись
	let sign = serverRSA.sign(msg, 'base64');
	//Упаковываем в обьект сообщение и ключ
	let mes =  {
		msg: clientRSA.encrypt(msg, 'base64'),
		sign: sign
	}
	//Отправляем в json
    client.write( JSON.stringify(mes));
}

rl.on('line', function (line) {
	 sendMsg(color.red(username+": ")+line); 
});

//Эту фукнцию надо явно преписать
function isPuplicKey (key) {
	if(key.indexOf("BEGIN PUBLIC KEY-----")>0) {
		return true;
	} else return false;
}