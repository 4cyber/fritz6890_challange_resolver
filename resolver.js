const crypto = require("crypto");
const { promisify } = require("util");
const pbkdf2Async = promisify(crypto.pbkdf2);

/**
 * Convert an hex string to a dec array
 * @param {string} string The hex string to convert, ex AAF0E9...
 * @returns dec array of the given hex string
 */
const stringHexToDec = (string) => {
    if (string.length % 2 > 0) throw new error("Errore lunghezza stringa hex");
    let ret = [];
    for (const hex of string.match(/.{1,2}/g)) {
        ret.push(parseInt(hex, 16));
    }
    return ret;
};

const asciiToDec = (ascii) => {
    //TODO an hex control length
    let ret = [];
    for (const valore of ascii.split("")) {
        ret.push(valore.charCodeAt(0));
    }
    return ret;
};

//convert array to buffer
const ArrayToArrayBuffer = (val) => new Uint8Array(val);

//convert buffer into array
const BufferToArray = (buffer) => [...buffer];

//convert array in hex string
const ArrayToHexString = (arr) => {
    let ret = "";
    arr.map((val) => {
        ret += val.toString(16).padStart(2, "0");
    });
    return ret;
};

const crack = (challenge) => {
    return new Promise(async (resolve, reject) => {
        try {
            let challengeSplit = challenge.split("$");

            //converto i vari hex in valori dec
            let pass = ArrayToArrayBuffer(asciiToDec(process.env.PASSWORD)),
                vals = {
                    salt1: ArrayToArrayBuffer(
                        stringHexToDec(challengeSplit[2])
                    ),
                    salt2: ArrayToArrayBuffer(
                        stringHexToDec(challengeSplit[4])
                    ),
                    iterations1: parseInt(challengeSplit[1]),
                    iterations2: parseInt(challengeSplit[3]),
                };

            let pbkdf2One = await pbkdf2Async(
                    pass,
                    vals.salt1,
                    vals.iterations1,
                    32,
                    "sha256"
                ),
                pbkdf2Two = await pbkdf2Async(
                    pbkdf2One,
                    vals.salt2,
                    vals.iterations2,
                    32,
                    "sha256"
                );

            let key1 = ArrayToHexString(BufferToArray(vals.salt2)),
                key2 = ArrayToHexString(BufferToArray(pbkdf2Two)),
                ChallengeResponse = [key1, key2].join("$");

            resolve(ChallengeResponse);
        } catch (error) {
            console.log("Errore");
            reject(error);
        }
    });
};

module.exports = crack;
