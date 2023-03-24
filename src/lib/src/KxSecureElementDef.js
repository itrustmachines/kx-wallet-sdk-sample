
export function get_initialize_device_default_config(){
	return{
		"transport_pin": false,
		"user_pin": "648219",
		"original_so_pin": "57621880",
		"new_so_pin": "57621880",
		"max_pin_retry_count": 3,
		"number_of_DKEK": 1,
		"use_fingerprint": true
	}
}

export const HSM_RSA_KEY_SIZE = {
	rsa_1024: 1024,
	rsa_1536: 1536,
	rsa_2048: 2048
}

export const HSM_EC_KEY_CURVE = {
	hsm_ec_secp256r1: 0x02,
	hsm_ec_secp256k1: 0x08
}

export const KX_ASYMMETRIC_KEY_TYPE = {
	NA: "NA",
    RSA: "RSA",
    ECC: "ECC"
}

export const RSA_SHA_256 = {
	asn1: [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
	oid: "1.2.840.113549.1.1.11"
}

export const RSA_ENCRYPTION = {
	asn1: [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
	oid: "1.2.840.113549.1.1.1"
}

export const RSA_V1_5_SHA_256 = {
	asn1: [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02],
	oid: "0.4.0.127.0.7.2.2.2.1.2"
}

export const ECDSA_SHA_256 = {
	asn1: [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03],
	oid: "0.4.0.127.0.7.2.2.2.2.3"
}
