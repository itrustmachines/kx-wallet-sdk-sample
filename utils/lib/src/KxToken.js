import KxSecureElement from "./KxSecureElement.js";
import { KX_ASYMMETRIC_KEY_TYPE } from "./KxSecureElementDef.js";
import { Data, 
         RSAPrivateKey,
         RSAPublicKey,
         ECCPrivateKey,
         ECCPublicKey,
         X509Certificate } from "./KxObject.js";
import { asn1Parser } from "./kxutils.js";
import Certificate from "../external/PKI.js/Certificate.js";
import {default as pkiRSAPublicKey} from "../external/PKI.js/RSAPublicKey.js";
import * as asn1js from "../external/ASN1.js/asn1.js";

export default class KxToken {

    constructor() {
        this.mKxSecureElement = new KxSecureElement();
        // this.mData = new Data(this.mKxSecureElement);
        
        this.mRSAPrivateKeys = [];
        this.mECCPrivateKeys = [];
        this.mX509Certs = [];
        this.mCACerts = [];
        this.mKeyCerts = [];
        this.mData = [];
    }
    
    /**
     * Initialize the SDK and connect with the token.
     * @returns {Boolean} Return true when initializing complete, false if failed.
     */
    init() {
        return this.mKxSecureElement.connect().then(() => {
            return this.mKxSecureElement.getApiVersion();
        }).then((result) => {
            console.log(`API version: ${result}`);
            return true;
        }).catch(() => {
            console.error("Cannot connect");
            return false;
        })
    }
    /**
     * User authentication using user pin code.
     * @param {String} userPin 
     * @returns {Boolean | Number} Returns true when login succeeds.
     * If login failed, returns either false or number of retry count.
     */
    login(userPin) {
        return this.mKxSecureElement.login(userPin);
    }
    /**
     * User authentication using biometric.
     * @returns {Boolean | Number} Returns true when login succeeds.
     * If login failed, returns either false or number of retry count.
     */
     loginBiometricAuto() {
        return this.mKxSecureElement.loginBiometricAuto();
    }
    /**
     * Query the information of the token.
     * @returns {Object} An object containing information of current status.
     * Object: {
     *     isUserPinBlocked: Boolean
     *     isUserLoggedIn:   Boolean
     *     userTryCntLeft:   {Number | NaN}
     *     isSOPinBlocked:   Boolean
     *     SOTryCntLeft:     Number
     * }
     */
    async getTokenInfo() {
        let userStatus = await this.mKxSecureElement.queryLoginStatus();
        let soStatus = await this.mKxSecureElement.querySoPinStatus();

        return {
            isUserPinBlocked: (userStatus === -1)? true : false,
            isUserLoggedIn: userStatus,
            userTryCntLeft: (typeof userStatus == 'number')? userStatus : NaN,
            isSOPinBlocked: (soStatus === -1)? true : false,
            SOTryCntLeft: (soStatus > 0)? soStatus : 0,
        }
    }
    /**
     * Unblock user pin with so pin.
     * @param {String} soPin 
     * @returns {Boolean | Number} Returns true if the process succeeds.
     * Else, returns either false or the number of retry count when SO pin is fault.
     */
    async unblockPin(soPin) {
        return await this.mKxSecureElement.resetLoginCounter(soPin);
    }
    /**
     * Change user pin.
     * @param {String} oldPin 
     * @param {String} newPin 
     * @returns {Boolean | Number} Returns true if the process succeeds.
     * Else, returns either false or the number of retry count when the user pin is fault.
     */
    async changePin(oldPin, newPin) {
        return await this.mKxSecureElement.changeUserPin(oldPin, newPin);
    }
    /**
     * Change SO pin.
     * @param {String} oldPin 
     * @param {String} newPin 
     * @returns {Boolean | Number} Returns true if the process succeeds.
     * Else, returns either false or the number of retry count when the SO pin is fault.
     */
    async changeSOPin(oldPin, newPin) {
        return await this.mKxSecureElement.changeSoPin(oldPin, newPin);
    }
    /**
     * Reset retry count of user pin.
     * @param {String} soPin 
     * @param {String} newUserPin 
     * @returns {Boolean | Number} Returns true if the process succeeds.
     * Else, returns either false or the number of retry count when the SO pin is fault.
     */
    async resetPin(soPin, newUserPin) {
        return await this.mKxSecureElement.changeUserPinBySoPin(soPin, newUserPin);
    }

    /**
     * Get a list of objects of the specified type.
     * @param {Class} type 
     * @param {Number} index 
     * @returns Either an object or list of object.
     */
    async getObjectList(type, index=null) {
        if (type === "Data") {
            if (this.mData.length === 0) {
                this.mData = await this._refreshObjectList(type);
            }

            if (typeof index === "number") {
                let found;
                for(let i = 0; i < this.mData.length; ++i) {
                    found = ((this.mData[i].containerFid & 0xFF) === index)? this.mData[i]: false;
                    if (found)
                        break;
                }
                return found;
            }
            return this.mData;
        } else if (type === "RSAPublicKey") {

        } else if (type === "RSAPrivateKey") {
            if (this.mRSAPrivateKeys.length === 0) {
                [this.mRSAPrivateKeys, this.mECCPrivateKeys, this.mKeyCerts] = await this._refreshObjectList("PrivateKey");
            }

            if (typeof index === "number") {
                let found;
                for(let i = 0; i < this.mRSAPrivateKeys.length; ++i) {
                    found = ((this.mRSAPrivateKeys[i].keyIndex) === index)? this.mRSAPrivateKeys[i]: false;
                    if (found)
                        break;
                }
                return found;
            }
            return this.mRSAPrivateKeys;
        } else if (type === "ECCPublicKey") {

        } else if (type === "ECCPrivateKey") {
            if (this.mECCPrivateKeys.length === 0) {
                [this.mRSAPrivateKeys, this.mECCPrivateKeys, this.mKeyCerts] = await this._refreshObjectList("PrivateKey");
            }

            if (typeof index === "number") {
                let found;
                for(let i = 0; i < this.mECCPrivateKeys.length; ++i) {
                    found = ((this.mECCPrivateKeys[i].keyIndex) === index)? this.mECCPrivateKeys[i]: false;
                    if (found)
                        break;
                }
                return found;
            }
            return this.mECCPrivateKeys;
        } else if (type === "X509Certificate") {
            if ((this.mRSAPrivateKeys.length === 0) && (this.mECCPrivateKeys.length === 0)) {
                [this.mRSAPrivateKeys, this.mECCPrivateKeys, this.mKeyCerts] = await this._refreshObjectList("PrivateKey");
            }
            if (this.mCACerts.length === 0) {
                this.mCACerts = await this._refreshObjectList("X509Certificate");
            }

            this.mX509Certs = this.mKeyCerts.concat(this.mCACerts);

            if (typeof index === "number") {
                if (index >= this.mX509Certs.length) {
                    return false;
                }
                return this.mX509Certs[index];
            }
            return this.mX509Certs;
        }
    }
    /**
     * Create a data object to be stored in the token.
     * @param {*} dataInfo 
     * @returns {Promise<Object>} Returns an object of the created data.
     */
    async createData(dataInfo) {
        let dataObject = await this.mKxSecureElement.createData(dataInfo);
        this.mData = [];
        return new Data(this.mKxSecureElement, dataObject);
    }

    /**
     * Create an RSA asymmetric key.
     * @param {*} keyInfo 
     * @returns {Promise<RSAPrivateKey>} Returns an object of the created RSA key.
     */
    async createRSAPrivateKey(keyInfo) {
        let keyObject = await this.mKxSecureElement.createKey(keyInfo);
        this.mRSAPrivateKeys = [];
        return new RSAPrivateKey(this.mKxSecureElement, keyObject);
    }

    /**
     * Create an ECC asymmetric key.
     * @param {*} keyInfo 
     * @returns {Promise<ECCPrivateKey>} Returns an object of the created ECC key.
     */
    async createECCPrivateKey(keyInfo) {
        let keyObject = await this.mKxSecureElement.createKey(keyInfo);
        this.mECCPrivateKeys = [];
        return new ECCPrivateKey(this.mKxSecureElement, keyObject);
    }

    async importPublicKeyCertificate(certData) {
        console.log(certData);
        let asn1 = asn1js.fromBER(certData);
	    let certificate = new Certificate({schema: asn1.result});

        const subjectCommonName = certificate.subject.typesAndValues[0].value.valueBlock.value;

        let modulus_SHA1;
        if(certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
        {
            const asn1PublicKey = asn1js.fromBER(certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
            const rsaPublicKey = new pkiRSAPublicKey({ schema: asn1PublicKey.result });
            
            const modulusView = new Uint8Array(rsaPublicKey.modulus.valueBlock.valueHex);
            modulus_SHA1 = await crypto.subtle.digest('SHA-1', modulusView);
        }

        let certInfo = {
            certIndex: undefined,
            label: subjectCommonName,
            id: modulus_SHA1,
            value: certData
        }

        console.log(certInfo);
        let certObject = await this.mKxSecureElement.createCert(certInfo);
        this.mCACerts = [];
        return new X509Certificate(this.mKxSecureElement, certObject);
    }

    /**
     * Delete the object.
     * @param {*} object 
     * @returns {Boolean} Returns true if the process succeeds, otherwise false.
     */
    async deleteObject(object) {
        if (object instanceof Data) {
            let result =  await this.mKxSecureElement.deleteData(object.containerFid);
            if (result) {
                this.mData = [];
            }
            return result;
        } else if (object instanceof RSAPublicKey) {
            console.error('Not implemented');
        } else if (object instanceof RSAPrivateKey) {
            let result =  await this.mKxSecureElement.deleteKey(object.keyIndex);
            if (result) {
                this.mRSAPrivateKeys = [];
            }
            return result;
        } else if (object instanceof ECCPublicKey) {
            console.error('Not implemented');
        } else if (object instanceof ECCPrivateKey) {
            let result =  await this.mKxSecureElement.deleteKey(object.keyIndex);
            if (result) {
                this.mECCPrivateKeys = [];
            }
            return result;
        } else if (object instanceof X509Certificate) {
            let result =  await this.mKxSecureElement.deleteCert(object.certIndex);
            if (result) {
                this.mCACerts = [];
            }
            return result;
        }
    }
    /**
     * 
     * @param {Number} byteSize 
     * @returns {Uint8Array} Generate a random value of byteSize.
     */
    async generateRandomValue(byteSize = 1) {
        return await this.mKxSecureElement.randomNumber(byteSize);
    }
    /**
     * 
     * @param {String} type "Data", "PrivateKey", "X509Certificate"
     */
    async _refreshObjectList(type) {
        if (type === "Data") {
            let mData = [];
                let dataList = await this.mKxSecureElement.enumerateData();
                for (let i = 0; i < dataList.length; ++i) {
                    // perhaps renaming KxSecureElement.getDataObject to getDataObjectInfo?
                    let result = await this.mKxSecureElement.getDataObject(dataList[i]);
                    mData.push(new Data(this.mKxSecureElement, result));
                }
            return mData;
        } else if (type === "PrivateKey") {
            let mRSAPrivateKeys = [];
            let mECCPrivateKeys = [];
            let mKeyCerts = [];
            let keyList = await this.mKxSecureElement.enumerateKey();
            for (let i = 0; i < keyList.length; ++i) {
                try {
                    let result = await this.mKxSecureElement.getKeyObject(keyList[i]);
                    // Get private key objects
                    if (result.keyType === KX_ASYMMETRIC_KEY_TYPE.RSA) {
                        mRSAPrivateKeys.push(new RSAPrivateKey(this.mKxSecureElement, result));
                    } else if (result.keyType === KX_ASYMMETRIC_KEY_TYPE.ECC) {
                        mECCPrivateKeys.push(new ECCPrivateKey(this.mKxSecureElement, result));
                    }
                    // Get Key based private key objects
                    if (result.isCertificate === true) {
                        let certObject = asn1Parser.certObjectInfo(result.publicKey);
                        certObject.certIndex = result.keyIndex;
                        certObject.value = result.publicKey;
                        mKeyCerts.push(new X509Certificate(this.mKxSecureElement, certObject));
                    }
                }catch(e) {
                    console.error(`Key#${i} ${e}`);
                }
            }
            return [mRSAPrivateKeys, mECCPrivateKeys, mKeyCerts];
        } else if (type === "X509Certificate") {
            let mCACerts = [];
            let certList = await this.mKxSecureElement.enumerateCert();
            for (let i = 0; i < certList.length; ++i) {
                let result = await this.mKxSecureElement.getCertObject(certList[i]);
                mCACerts.push(new X509Certificate(this.mKxSecureElement, result));
            }
            return mCACerts;
        }
    }

    async importCert(certData) {
        /**
         * Check with Private Key
         */
        if (this.mRSAPrivateKeys.length === 0)
            [this.mRSAPrivateKeys, this.mECCPrivateKeys, this.mKeyCerts] = await this._refreshObjectList("PrivateKey");

        // Get cert Info, modulus, common name, email
        let asn1 = asn1js.fromBER(certData);
	    let certificate = new Certificate({schema: asn1.result});

    	let publicKeySize = "< unknown >";
        let modulusView;
        if(certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
        {
            const asn1PublicKey = asn1js.fromBER(certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
            const rsaPublicKey = new pkiRSAPublicKey({ schema: asn1PublicKey.result });
            
            modulusView = new Uint8Array(rsaPublicKey.modulus.valueBlock.valueHex);
            let modulusBitLength = 0;
            
            if(modulusView[0] === 0x00)
                modulusBitLength = (rsaPublicKey.modulus.valueBlock.valueHex.byteLength - 1) * 8;
            else
                modulusBitLength = rsaPublicKey.modulus.valueBlock.valueHex.byteLength * 8;
            
            publicKeySize = modulusBitLength;
        }

        const subjectCommonName = certificate.subject.typesAndValues[1].value.valueBlock.value;
        const subjectEmail = certificate.subject.typesAndValues[0].value.valueBlock.value;

        // Match modulus with any rsa key that is not certificate
        let key;
        for (let i = 0; i < this.mRSAPrivateKeys.length; ++i) {
            if (this.mRSAPrivateKeys[i].isCertificate === false) {
                if (this.mRSAPrivateKeys[i]._matchCertModulus(modulusView) === true) {
                    key = this.mRSAPrivateKeys[i];
                    break;
                }
            }
        }

        if (key instanceof RSAPrivateKey)
        {
            // get key uid
            asn1 = asn1js.fromBER(key.privateKeyInfo);
            const privateKeyInfo = asn1.result;
    
            const keyUid = 
                privateKeyInfo.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex;
    
            // import cert
            let certInfo = {
                keySizeBits: publicKeySize,
                label: subjectCommonName,
                id: keyUid,
                common: subjectCommonName,
                email: subjectEmail
            };
    
            /* NOTE(Steven) TODO:
             * Change import cert API into importCert(key.keyIndex, certData)
             * In which certData is:
             * certData = {
             *   info = {
             *     label,
             *     id,
             *     common,
             *     email
             *   },
             *   value
             * }
             */
            let result = await this.mKxSecureElement.importCert(key.keyIndex, certInfo, certData);
            this.mRSAPrivateKeys = []
            return result;
        }
        /** End region ***********************************************************************/

        /**
         * Check with CA's certificate
         */
        if (this.mCACerts.length === 0)
            this.mCACerts = await this._refreshObjectList("X509Certificate");
 
        // Get certificate's public key hash
        let modulus_SHA1;
        if(certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
            modulus_SHA1 = await crypto.subtle.digest('SHA-1', modulusView);

        // match with existing certificate
        let caCert;
        for (let i = 0; i < this.mCACerts.length; ++i) {
            if (this.mCACerts[i]._matchRSACertModulusSHA1(new Uint8Array(modulus_SHA1)) === true) {
                caCert = this.mCACerts[i];
                break;
            }
        }
 
        if (caCert === undefined) {
            let certInfo = {
                certIndex: undefined,
                label: subjectEmail,
                id: modulus_SHA1,
                value: certData
            }
     
            console.log(certInfo);
            this.mKxSecureElement.createCert(certInfo).then(() => {
                this.mCACerts = [];
            });
        }
        /** End region ********************************************************************** */
        return true;
    }

    apduExchange(command) {
        return this.mKxSecureElement.apduExchange(command).then(response => {
            return {
                sw: response.sw,
                response: response.data.buffer
            }
        });
    }
}