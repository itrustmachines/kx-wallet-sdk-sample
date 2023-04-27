import { KX_ASYMMETRIC_KEY_TYPE,
         RSA_ENCRYPTION,
         RSA_V1_5_SHA_256,
         ECDSA_SHA_256 } from "./KxSecureElementDef.js";
import * as asn1js from "../external/ASN1.js/asn1.js";
import Certificate from "../external/PKI.js/Certificate.js";

const HSM_FILE_ID_PREFIX = {
	private_key_info: 0xC400,
	certificate_info: 0xC800,
	data_container_info: 0xC900,
	ca_certificate: 0xCA00,
	read_only_data_object: 0xCB00,
	private_key: 0xCC00,
	confidential_data: 0xCD00,
	ee_certificate: 0xCE00,
	public_data: 0xCF00,
}

export function hex2array(string)
{
    if (string.slice(0,2) === '0x')
    {
        string = string.slice(2,string.length);
    }
    if (string.length & 1)
    {
        throw new Error('Odd length hex string');
    }
    let arr = new Uint8Array(string.length/2);
    var i;
    for (i = 0; i < string.length; i+=2)
    {
        arr[i/2] = parseInt(string.slice(i,i+2),16);
    }
    return arr;
}

export function array2hex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

export var asn1Parser = {
    isCertificate: (buffer) => {
        const cert_tag = [0x30, 0x82];
        let view = new DataView(buffer);
        return (view.getUint8(0) === cert_tag[0] && view.getUint8(1) === cert_tag[1]);
    },

    /**
     * Variable naming rule follows the name from ASN1
     * @param {*} isCertificate 
     * @param {*} arrayBuffer 
     * @returns 
     */
    keyType: (isCertificate, arrayBuffer) => {
        let asn1 = asn1js.fromBER(arrayBuffer);
        if (isCertificate) {
	        let certificate = new Certificate({schema: asn1.result});
            if (certificate.subjectPublicKeyInfo.algorithm.algorithmId === RSA_ENCRYPTION.oid)
                return KX_ASYMMETRIC_KEY_TYPE.RSA;
        } else {
            let app7 = asn1.result;
            let app33 = app7.valueBlock.value[0];
            let app78 = app33.valueBlock.value[0];
            let app73 = app78.valueBlock.value[2];
            let oid = app73.valueBlock.value[0];

            if (oid.valueBlock.toString() === RSA_V1_5_SHA_256.oid)
                return KX_ASYMMETRIC_KEY_TYPE.RSA;
            else if (oid.valueBlock.toString() === ECDSA_SHA_256.oid)
                return KX_ASYMMETRIC_KEY_TYPE.ECC
        }
    },

    dataObjectInfo: (arrayBuffer) => {
        let dataObject = {
            containerFid: null,
            dataFid: null,
            isPrivate: null,
            label: null,
            appInfo: null,
            oid: null,
            value: null
        };

        // Follows the asn1 structure
        let asn1 = asn1js.fromBER(arrayBuffer);
        let root_seq = asn1.result;
            // root sequence's child[0] sequence
            let rs_c0seq = root_seq.valueBlock.value[0];
                dataObject.label = rs_c0seq.valueBlock.value[0].valueBlock.value;
            let rs_c1seq = root_seq.valueBlock.value[1];
                dataObject.appInfo = rs_c1seq.valueBlock.value[0].valueBlock.value;
            // Complete object
            if (root_seq.valueBlock.value.length === 4) {
                dataObject.oid = root_seq.valueBlock.value[2].valueBlock.toString();
                let rs_context1 = root_seq.valueBlock.value[3];
                    let context1_seq = rs_context1.valueBlock.value[0];
                        let fid_array = new Uint8Array(context1_seq.valueBlock.value[0].valueBlock.valueHex);
                        dataObject.dataFid = (fid_array[0] << 8) | fid_array[1];
            } else {
                // Incomplete object, missing OID (created from Xenbox)
                let rs_context1 = root_seq.valueBlock.value[2];
                    let context1_seq = rs_context1.valueBlock.value[0];
                        let fid_array = new Uint8Array(context1_seq.valueBlock.value[0].valueBlock.valueHex);
                        dataObject.dataFid = (fid_array[0] << 8) | fid_array[1];
            }

        if ((dataObject.dataFid & 0xFF00) === HSM_FILE_ID_PREFIX.confidential_data)
            dataObject.isPrivate = true;
        else
            dataObject.isPrivate = false;
        return dataObject;
    },

    certObjectInfo: (arrayBuffer) => {
        let certObject = {
            certIndex: null,
            label: null,
            id: null,
            value: null
        }

        // Follows the asn1 structure
        let asn1 = asn1js.fromBER(arrayBuffer);
        let root_seq = asn1.result;
            // root sequence's child[0] sequence
            let rs_c0seq = root_seq.valueBlock.value[0];
                certObject.label = rs_c0seq.valueBlock.value[0].valueBlock.value;
            let rs_c1seq = root_seq.valueBlock.value[1];
                certObject.id = rs_c1seq.valueBlock.value[0].valueBlock.valueHex;
        return certObject;
    }
};

export function ArrayBufferToBase64(buffer) {
    //The first step is to convert the ArrayBuffer to a binary string
	var binary = '';
	var bytes = new Uint8Array(buffer);
	for (var len = bytes.byteLength, i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
         //Convert binary string to base64 string
	return window.btoa(binary);
}