//crypto 모듈 : 암호화 목적
const crypto = require('crypto');
//파일 시스템 
const fs = require('fs');


const privateKeyFileName = 'C:/Users/atlas/Documents/signPem/pri_signtest.myskcdn.net.pem';
fs.readFile(privateKeyFileName, (err, data) => console.log(data));
const keyPairId = '';
const urlPath = '';
const expires = Date.now() + 21600;
const clientIp = '';
//signed url policy : 3가지 => 경로확인, url 만료 기간, 요청 ip 주소 확인 
const policy = JSON.stringify({
    Statement: [
        {
            Resource: "http*://signtest.myskcdn.net/*",
            Condition: {
                DateLessThan: {
                    "AWS:EpochTime": `${expires}`
                },
                IpAddress: { "AWS:SourceIp": `${clientIp}` }
            }
        }
    ]
});




const rsaSha1Sign = (policy, privateKeyFileName) => {
    let signature = '';

    //Buffer : 바이너리 데이터들의 스트림을 읽거나, 조작하는 메커니즘
    //데이터가 버퍼에 있는동안 스트리밍 되는 데이터를 조작할 수 있다. 

    try {
        const privateKey = fs.readFileSync(privateKeyFileName, 'utf8');
        if (privateKey.length > 8192) throw 'Wrong file!';

        const sign = crypto.createSign('RSA-SHA1');
        sign.update(policy);
        signature = sign.sign(privateKey, 'base64');

        return signature;
    }
    catch (err) {
        console.log(err);
    }


    // fs.close(fd);
    // console.log(fs)


};
console.log(rsaSha1Sign(policy, privateKeyFileName));
const urlSafeBase64Encode = () => { };

const urlSafeBase64Encode1 = () => {

};

const createStreamName = () => {

};

const encodeQueryParams = () => { };

const getCustomPolicyStreamName = () => { };

const customPolicyStreamName = getCustomPolicyStreamName()