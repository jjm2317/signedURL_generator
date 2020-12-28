//crypto 모듈 : 암호화 목적
const { POINT_CONVERSION_COMPRESSED } = require('constants');
const crypto = require('crypto');
const { create } = require('domain');
//파일 시스템 
const fs = require('fs');


const privateKeyFileName =;
fs.readFile(privateKeyFileName, (err, data) => console.log(data));
const keyPairId = 'pub_signtest.myskcdn.net';
const urlPath = 'http://signtest.myskcdn.net/skcdn.mp4';
const expires = Date.now() + 21600;
const clientIp = '0.0.0.0/0';
const waterMark = "1010101101"
//signed url policy : 3가지 => 경로확인, url 만료 기간, 요청 ip 주소 확인 
const policy = JSON.stringify({
    Statement: [
        {
            Resource: "http*://signtest.myskcdn.net/*",
            Condition: {
                DateLessThan: {
                    "AWS:EpochTime": `${expires}`
                },
                IpAddress: { "AWS:SourceIp": `${clientIp}` },
                WaterMark: {
                    Binary: `${waterMark}`
                }
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
    return value.replace(/[+=\/]/ig, match => match === '+' ? '-' : (match === '=' ? '_' : '~'));
};
console.log(urlSafeBase64Encode(rsaSha1Sign(policy, privateKeyFileName)));


const createStreamName = (stream, policy, signature, keyPairId, expires) => {
    let path = "";
    let result = stream;
    const separator = stream.match(/\?/) ? '&' : '?';
    if (expires) {
        result += `${path + separator}Expires=${expires}&Signature=${signature}&Key-Pair-Id=${keyPairId}`;
    } else {
        result += `${path + separator}Policy=${policy}&Signature=${signature}&Key-Pair-Id=${keyPairId}`;
    }
    return result.replace(/\n/ig, '');
};

const encodeQueryParams = () => { };

const getCustomPolicyStreamName = (urlPath, privateKeyFileName, keyPairId, policy) => {
    const encodedPolicy = urlSafeBase64Encode(policy);
    const signature = rsaSha1Sign(policy, privateKeyFileName);
    const encodedSignature = urlSafeBase64Encode(signature);

    const streamName = createStreamName(urlPath, encodedPolicy, encodedSignature, keyPairId, expires);
    return streamName;
};

const customPolicyStreamName = getCustomPolicyStreamName(urlPath, privateKeyFileName, keyPairId, policy);
console.log(customPolicyStreamName);