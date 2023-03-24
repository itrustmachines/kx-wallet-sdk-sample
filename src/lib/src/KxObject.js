import * as asn1js from "../external/ASN1.js/asn1.js";
import { default as pkiCertificate } from "../external/PKI.js/Certificate.js";
import {default as pkiRSAPublicKey} from "../external/PKI.js/RSAPublicKey.js";

class Object {
    constructor(se_handle) {
        this.mKxSecureElement = se_handle;
    }
}

export class Data extends Object {
    constructor(se_handle, dataInfo) {
        super(se_handle);
    
        this.containerFid = dataInfo.containerFid;
        this.dataFid = dataInfo.dataFid;
        this.isPrivate = dataInfo.isPrivate;
        this.label = dataInfo.label;
        this.appInfo = dataInfo.appInfo;
        this.oid = dataInfo.oid;
        this.value = dataInfo.value;
    }
}

class AsymmetricKey extends Object {
    constructor(se_handle, keyObject) {
        super(se_handle);

        this._keyObject = keyObject;
        this.keyIndex = keyObject.keyIndex;
        this.keyType = keyObject.keyType;
        this.isCertificate = keyObject.isCertificate;
        this.publicKey = keyObject.publicKey;
        this.privateKeyInfo = keyObject.privateKeyInfo;
        this.label = this.getKeyLabel();
    }

    getKeyLabel() {
        const asn1 = asn1js.fromBER(this.privateKeyInfo).result;
        return asn1.valueBlock.value[0]
            .valueBlock.value[0]
            .valueBlock.value;
    }
}

class PublicKey extends AsymmetricKey {
    constructor(se_handle, keyObject) {
        super(se_handle);
    }
}

class PrivateKey extends AsymmetricKey {
    constructor(se_handle, keyObject) {
        super(se_handle, keyObject);
    }

    // wrap private key
}

export class RSAPublicKey extends PublicKey {
    constructor() {

    }

    // get public key info
}

export class RSAPrivateKey extends PrivateKey {
    constructor(se_handle, keyObject) {
        super(se_handle, keyObject);
    }
    // rsa sign
    async rsaSignRaw(contentData) {
        return await this.mKxSecureElement.sign(this._keyObject, contentData);
    }
    /**
     * 
     * @param {ArrayBuffer | ArrayBufferView} contentData 
     */
    async rsaSignPKCS1v15(contentData) {
        // hash
        let digest = await crypto.subtle.digest('SHA-256', contentData);
        let digestInfo = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: "2.16.840.1.101.3.4.2.1" }),    // sha256
                        new asn1js.Null()
                    ]
                }),
                new asn1js.OctetString({ valueHex: digest }),
            ]
        });
        let digestInfoValue = new Uint8Array(digestInfo.toBER(false));

        const privateKeyInfo_view = new Uint8Array(this.privateKeyInfo);
        let keySizeOffset = privateKeyInfo_view.length - 2;
        let keySize_Bits = (privateKeyInfo_view[keySizeOffset] << 8) | privateKeyInfo_view[keySizeOffset+1];
        let keySize_Bytes = keySize_Bits / 8;

        // pad
        const digestInfoValue_startOffset = keySize_Bytes - digestInfoValue.length;

        let encodedData = new Uint8Array(keySize_Bytes);
        encodedData[0] = 0x00;
        encodedData[1] = 0x01;

        encodedData.fill(0xFF, 2, digestInfoValue_startOffset-1);

        encodedData[digestInfoValue_startOffset-1] = 0x00;
        for (let i = 0; i < digestInfoValue.length; ++i) {
            encodedData[digestInfoValue_startOffset + i] = digestInfoValue[i];
        }

        // rawSign
        return await this.mKxSecureElement.sign(this._keyObject, encodedData);
    }

    testRsaV15Sign(contentData) {
        return this.mKxSecureElement.rsaV1_5Sign(this._keyObject, contentData).then(result => {
            return result;
        });
    }

    /**
     * 
     * @param {*} certModulusView 
     * @returns {Boolean} Return true if both modulus matched.
     */
    _matchCertModulus(certModulusView) {
        let asn1 = asn1js.fromBER(this.publicKey);
        let modulusView = 
            asn1.result.valueBlock.value[0].
            valueBlock.value[0].
            valueBlock.value[2].
            valueBlock.value[1].
            valueBlock.valueHex;
        modulusView = new Uint8Array(modulusView);

        if (modulusView.length !== certModulusView.length)
            return false;
        for (let i = 0; i < modulusView.length; ++i) {
            if (modulusView[i] !== certModulusView[i])
                return false;
        }
        return true;
    }
}

export class ECCPublicKey extends PublicKey {
    constructor() {

    }
    // get public key info
}

export class ECCPrivateKey extends PrivateKey {
    constructor(se_handle, keyObject) {
        super(se_handle, keyObject);
    }
    //get private key object info
    
    async SignRaw(contentData) {
        return await this.mKxSecureElement.sign(this._keyObject, contentData);
    }
}

class Certificate extends Object {
    constructor(se_handle, certInfo) {
        super(se_handle);

        let asn1 = asn1js.fromBER(certInfo.value);
	    let certificate = new pkiCertificate({schema: asn1.result});

        this.certIndex = certInfo.certIndex;
        this.label = certInfo.label;
        this.id = certInfo.id;
        this.value = certInfo.value;
        this.certificate = certificate;
    }
}

export class X509Certificate extends Certificate {
    constructor(se_handle, certInfo) {
        super(se_handle, certInfo);
    }

    /**
     * 
     * @param {*} certModulusView 
     * @returns {Boolean} Return true if both modulus matched.
     */
     _matchRSACertModulusSHA1(certModulusSHA1View) {
        const asn1PublicKey = asn1js.fromBER(this.certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
        const rsaPublicKey = new pkiRSAPublicKey({ schema: asn1PublicKey.result });
        
        const modulusView = new Uint8Array(rsaPublicKey.modulus.valueBlock.valueHex);
        if (modulusView.length !== certModulusSHA1View.length)
            return false;
        for (let i = 0; i < modulusView.length; ++i) {
            if (modulusView[i] !== certModulusSHA1View[i])
                return false;
        }
        return true;
    }
}