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
};

//signature와 policy는 base64 encode 이후 +, =, / 을 각각 -, _, ~ 로 대체
const urlSafeBase64Encode = (value) => {
    value.replace('+', '-');
    value.replace('=', '_');
    value.replace('/', '~');
    return value;
};

// const urlSafeBase64Encode1 = () => {
// };

const createStreamName = () => {

};

const encodeQueryParams = () => { };

const getCustomPolicyStreamName = () => { };

const customPolicyStreamName = getCustomPolicyStreamName()