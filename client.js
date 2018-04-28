const net=require("net");
const NodeRSA = require('node-rsa');
const readline = require('readline');
const color = require('colors');

let client= new net.Socket();
const rl = readline.createInterface(process.stdin, process.stdout);

const port = process.argv[2];
const host = process.argv[3] || 'localhost'; // localhost - по умолчанию
const username =  process.argv[4] || 'Anonymous' // Anonymous - по умолчанию

// Создаем обьекты RSA для себя и сервера
let serverRSA  = new NodeRSA({b: 512});
let clientRSA  = new NodeRSA({b: 512});


client.connect(port, host, function(){
	console.log(`Connected to ${color.red(client.remoteAddress)}`);
	//Отправляем свой публичный ключ на сервер
	client.write(clientRSA.exportKey('public'))
});


client.on("data",function(data){
	//Если переданные данные являются публичным ключем
	if(isPuplicKey(data)) {
			//Импортируем серверный ключ в ранее созданный обьект
			serverRSA.importKey(data,'pkcs8-public');
			console.log(`Encrypted connection established \n`);
		 } else {
		 	message = JSON.parse(data);
			//Расшифровываем собщение своим публичным ключом
		 	msg = clientRSA.decrypt(message.msg, 'utf8');
			//Проверяем цифровую подпись сообщения
		 	if(serverRSA.verify(msg.toString(), message.sign.toString(), 'utf8', 'base64')) {
		 		console.log(color.green(msg));
		 	} else console.log(color.red("NOT VERYFED:"+msg)); 
		 }
			 
		
    
})

//Отправка сообщений
function sendMsg(msg){
	//Создаем цифровую подпись
	let sign = clientRSA.sign(msg, 'base64');
	//Упаковываем в обьект сообщение и ключ
	let mes =  {
		msg: serverRSA.encrypt(msg, 'base64'),
		sign: sign
	}
	//Отправляем в json
    client.write(JSON.stringify(mes));
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