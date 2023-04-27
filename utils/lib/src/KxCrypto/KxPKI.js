import * as asn1js from "../../external/ASN1.js/asn1.js";
import SignedData from "./KxSignedData.js";
import CertificationRequest from "./KxCertificationRequest.js";
import EncapsulatedContentInfo from "../../external/PKI.js/EncapsulatedContentInfo.js";
import Certificate from "../../external/PKI.js/Certificate.js";
import SignerInfo from "../../external/PKI.js/SignerInfo.js";
import IssuerAndSerialNumber from "../../external/PKI.js/IssuerAndSerialNumber.js";
import ContentInfo from "../../external/PKI.js/ContentInfo.js";
import AttributeTypeAndValue from "../../external/PKI.js/AttributeTypeAndValue.js";
import GeneralNames from "../../external/PKI.js/GeneralNames.js";
import GeneralName from "../../external/PKI.js/GeneralName.js";
import Attribute from "../../external/PKI.js/Attribute.js";
import Extension from "../../external/PKI.js/Extension.js";
import Extensions from "../../external/PKI.js/Extensions.js";

import {array2hex} from "../kxutils.js";

export function createCMSSigned(privateKey, dataBuffer, detachedSignature = false) {
	if (privateKey.isCertificate !== true) {
		console.error("The private key has not a valid certificate");
		return false;
	}

    //region Initial variables
	let sequence = Promise.resolve();
	let cmsSigned;

	// To meet the require for subtle.getSignatureParameters.
	privateKey.algorithm = {name: "RSASSA-PKCS1-v1_5"};
	let hashAlg = "SHA-256";

    let asn1 = asn1js.fromBER(privateKey.publicKey);
	let certificate = new Certificate({schema: asn1.result});
	
	//region Initialize CMS Signed Data structures and sign it
	sequence = sequence.then(
		() =>
		{
			cmsSigned = new SignedData({
				version: 1,
				encapContentInfo: new EncapsulatedContentInfo({
					eContentType: "1.2.840.113549.1.7.1" // "data" content type
				}),
				signerInfos: [
					new SignerInfo({
						version: 1,
						sid: new IssuerAndSerialNumber({
							issuer: certificate.issuer,
							serialNumber: certificate.serialNumber
						})
					})
				],
				certificates: [certificate]
			});

			if(detachedSignature === false)
			{
				const contentInfo = new EncapsulatedContentInfo({
					eContent: new asn1js.OctetString({ valueHex: dataBuffer })
				});
				
				cmsSigned.encapContentInfo.eContent = contentInfo.eContent;
				
				return cmsSigned.sign(privateKey, 0, hashAlg);
			}
			
			return cmsSigned.sign(privateKey, 0, hashAlg, dataBuffer);
		}
	);
	//endregion
	
	//region Create final result
	return sequence.then(
		() =>
		{
			const cmsSignedSchema = cmsSigned.toSchema(true);
			
			const cmsContentSimp = new ContentInfo({
				contentType: "1.2.840.113549.1.7.2",
				content: cmsSignedSchema
			});
			
			const _cmsSignedSchema = cmsContentSimp.toSchema();
			
			//region Make length of some elements in "indefinite form"
			_cmsSignedSchema.lenBlock.isIndefiniteForm = true;
			
			const block1 = _cmsSignedSchema.valueBlock.value[1];
			block1.lenBlock.isIndefiniteForm = true;
			
			const block2 = block1.valueBlock.value[0];
			block2.lenBlock.isIndefiniteForm = true;
			
			if(detachedSignature === false)
			{
				const block3 = block2.valueBlock.value[2];
				block3.lenBlock.isIndefiniteForm = true;
				block3.valueBlock.value[1].lenBlock.isIndefiniteForm = true;
				block3.valueBlock.value[1].valueBlock.value[0].lenBlock.isIndefiniteForm = true;
			}
			//endregion
			
			return _cmsSignedSchema.toBER(false);
		},
		error => Promise.reject(`Erorr during signing of CMS Signed Data: ${error}`)
	);
	//endregion
}

/**
 * DN: country name, label, email, 
 * @param DN
 * @type {string} countryName
 * @type {string} label
 * @type {string} email
 * 
 * @returns 
 */
export function createPKCS10(privateKey, hashAlg, DN) {
	//region Initial variables
	let sequence = Promise.resolve();

	privateKey.algorithm = {name: "RSASSA-PKCS1-v1_5",
							hash: hashAlg};
	
	const pkcs10 = new CertificationRequest();

	//endregion
	
	// //region Get a "crypto" extension
	// const crypto = getCrypto();
	// if(typeof crypto === "undefined")
	// 	return Promise.reject("No WebCrypto extension found");
	// //endregion
	
	//region Put a static values
	pkcs10.version = 0;
	pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6",
		value: new asn1js.PrintableString({ value: DN.countryName })
	}));
	pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3",
		value: new asn1js.Utf8String({ value: DN.label })
	}));
	
	const altNames = new GeneralNames({
		names: [
			new GeneralName({
				type: 1, // rfc822Name
				value: DN.email
			}),
			new GeneralName({
				type: 2, // dNSName
				value: "www.domain.com"
			}),
			new GeneralName({
				type: 2, // dNSName
				value: "www.anotherdomain.com"
			}),
			new GeneralName({
				type: 7, // iPAddress
				value: new asn1js.OctetString({ valueHex: (new Uint8Array([0xC0, 0xA8, 0x00, 0x01])).buffer })
			}),
		]
	});
	
	pkcs10.attributes = [];
	//endregion

	//region convert the key format to SubjectPublicKeyInfo 
	const publicKey = asn1js.fromBER(privateKey.publicKey).result;
	const publicKey_block = 
		publicKey.valueBlock.value[0]
		.valueBlock.value[0]
		.valueBlock.value[2];
	const modulus = 
		publicKey_block
		.valueBlock.value[1]
		.valueBlock.valueHex;
	let modulusView = new Uint8Array(modulus);
	let padModulusView = new Uint8Array(modulusView.length + 1);
	padModulusView.set(modulusView, 1);
	const exponent = 
		publicKey_block
		.valueBlock.value[2]
		.valueBlock.valueHex;
	
	const publicKeyInfo = new asn1js.Sequence({
		value: [
			new asn1js.Integer({ valueHex: padModulusView }),
			new asn1js.Integer({ valueHex: exponent })
		]
	});
	const spki = new asn1js.Sequence({
		value: [
			new asn1js.Sequence({
				value: [
					new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.1" }),
					new asn1js.Null()
				]
			}),
			new asn1js.BitString({
				valueHex: publicKeyInfo.toBER(false)
			})
		]
	});
	//endregion

	//region Convert our public key into type "CryptoKey"
	//for the sake of the next region
	sequence = sequence.then(() => {
		return crypto.subtle.importKey(
			"spki",
			spki.toBER(false),
			privateKey.algorithm,
			true,
			[]
		);
	});
	//endregion
	
	//region Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
	sequence = sequence.then(publicKey => pkcs10.subjectPublicKeyInfo.importKey(publicKey));
	//endregion
	
	//region SubjectKeyIdentifier
	sequence = sequence.then(() => crypto.subtle.digest({ name: hashAlg }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex))
		.then(result =>
		{
			pkcs10.attributes.push(new Attribute({
				type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
				values: [(new Extensions({
					extensions: [
						new Extension({
							extnID: "2.5.29.14",
							critical: false,
							extnValue: (new asn1js.OctetString({ valueHex: result })).toBER(false)
						}),
						new Extension({
							extnID: "2.5.29.17",
							critical: false,
							extnValue: altNames.toSchema().toBER(false)
						}),
						new Extension({
							extnID: "1.2.840.113549.1.9.7",
							critical: false,
							extnValue: (new asn1js.PrintableString({ value: "passwordChallenge" })).toBER(false)
						})
					]
				})).toSchema()]
			}));
		}
	);
	//endregion
	
	//region Signing final PKCS#10 request
	sequence = sequence.then(() => pkcs10.sign(privateKey, hashAlg), error => Promise.reject(`Error during exporting public key: ${error}`));
	//endregion
	
	return sequence.then(() =>
	{
		return pkcs10.toSchema().toBER(false);
		
	}, error => Promise.reject(`Error signing PKCS#10: ${error}`));
}