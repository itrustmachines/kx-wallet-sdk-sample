import { asn1Parser, hex2array, array2hex } from "./kxutils.js";
import { KX_ASYMMETRIC_KEY_TYPE } from "./KxSecureElementDef.js"
import kxSeApduApi from "./wasm/kxSeApduApi.js";

const HSM_STATUS_WORD = {
	success: 0x9000,
	wrong_pin_x_tries: 0x63C,
	wrong_length: 0x6700,
	incorrect_parameter: 0x6A86,
	incorrect_data: 0x6A80,
	security_status_not_satisfied: 0x6982,
	condition_not_satisfied: 0x6985,
	reference_data_not_found: 0x6A88,
	reference_data_not_usable: 0x6984,
	authentication_method_blocked: 0x6983,
	file_not_found: 0x6A82,
	eof_reached: 0x6282
}

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

const HSM_ERR_CODE = {
	hsm_err_undefined: -1,
    hsm_success: 0x00,
    hsm_err_invalid_command: 0x01,
    hsm_err_invalid_parameter: 0x02,
    hsm_err_invalid_length: 0x03,
	hsm_err_not_initialized: 0x04,
	hsm_err_ctap_error: 0x10
}

class objList {
    constructor() {
        this.element = null;
    }

    reset() {
        this.element = [];
    };

    /**
     * Check if element exists.
     * @param {Number} index The index of the object.
     * @returns Returns true or false.
     */
    isValid(index) {
        let element_index = this.element.map(fid => {return fid & 0xFF});
        return element_index.includes(index);
    };
}

export default class KxSecureElement {

	constructor() {
        this.seutil = new kxSeApduApi();
        this._keyList = new objList();
        this._dataContainerList = new objList();
        this._certList = new objList();
	}

    /**
	 * Get WASM api version
	 * @return {Promise.<T>|Promise}
	 */
	getApiVersion(){
		return this.seutil.version();
	}
    /**
     * @returns {String | Promise} Returns promise if failed.
     */
	connect(){
		return this.seutil.selectApplication().then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return response.data;
            else
                return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        });
	}
    /**
     * Login smart token.
     * @param {String} user_pin 
     * @returns {Boolean | Number | Promise} Return "true" if login success.
     *      Return retry count if login failed. Return promise if there's other error.
     *      Wrong pin length could be caught from promise.
     */
    login(user_pin){
        return this.seutil.verifyUserPin(user_pin).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return true;
            else if ((response.sw >>> 4 ) === HSM_STATUS_WORD.wrong_pin_x_tries)
                return response.sw & 0xF;
            // else if (response.sw == 0x6D00)
            //     this.connect();
            else {
                return false;
                // return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
            }
        });
    }
    /**
     * Check whether smart token is logged in.
     * @returns {Boolean | Number | Promise} Return "true" if logged in, else return retry counter.
     */
    queryLoginStatus(){
        return this.seutil.verifyUserPinStatus().then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return true;
            else if ((response.sw >>> 4 ) === HSM_STATUS_WORD.wrong_pin_x_tries)
                return response.sw & 0xF;
            else if (response.sw === HSM_STATUS_WORD.authentication_method_blocked)
                return -1;
            else
                return false;
                // return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        });
    }
    /**
     * Check SO pin retry count
     * @returns {Number | Promise} Retry counts.
     */
    querySoPinStatus(){
        return this.seutil.verifySoPinStatus().then(response => {
            if ((response.sw >>> 4 ) === HSM_STATUS_WORD.wrong_pin_x_tries)
                return response.sw & 0xF;
            else if (response.sw === HSM_STATUS_WORD.authentication_method_blocked)
                return -1;
            else
                return false;
                // return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        });
    }
    /**
     * Reset user pin retry counter
     * @param {String} so_pin 
     * @returns {Boolean | Number | Promise} Return "true" if reset success.
     *      Return retry count if so pin is wrong. Return promise if there's other error.
     *      Wrong pin length could be caught from promise.
     */
    resetLoginCounter(so_pin){
        return this.seutil.resetRetryCounter(so_pin).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return true;
            else if ((response.sw >>> 4 ) === HSM_STATUS_WORD.wrong_pin_x_tries)
                return response.sw & 0xF;
            else 
                return false;
                // return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        })
    }
    /**
     * @param {String} old_user_pin 
     * @param {String} new_user_pin 
     * @returns {Boolean | Number | Promise} Returns true when pin change succeed..
     *      Returns retry count if input pin is wrong.
     */
    changeUserPin(old_user_pin, new_user_pin){
        return this.seutil.changeUserPin(old_user_pin, new_user_pin).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return true;
            else if ((response.sw >>> 4 ) === HSM_STATUS_WORD.wrong_pin_x_tries)
                return response.sw & 0xF;
            else 
                return false;
                // return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        })
    }
    /**
     * @param {String} old_so_pin 
     * @param {String} new_so_pin 
     * @returns {Boolean} Returns true if change pin success, false instead.
     */
    changeSoPin(old_so_pin, new_so_pin){
        return this.seutil.changeSoPin(old_so_pin, new_so_pin).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return true;
            return false;
        });
    }
    /**
     * @param {String} so_pin 
     * @param {String} new_user_pin 
     * @returns {Boolean}
     */
    changeUserPinBySoPin(so_pin, new_user_pin){
        return this.seutil.changeUserPinBySoPin(so_pin, new_user_pin).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return true;
            return false;
        });
    }
/*
	async initializeToDefault(initialize_config){
		var ret = {
			"status": HSM_ERR_CODE.hsm_err_undefined,
			"resp": null,
			"data": null,
			"sw": 0
		};
		let user_pin = initialize_config.user_pin;
		let so_pin = initialize_config.original_so_pin;
		let try_cnt = initialize_config.max_pin_retry_count;
		let dkek_num = initialize_config.number_of_DKEK;
		let is_transport = initialize_config.transport_pin;
		let is_fingerprint = initialize_config.use_fingerprint;
		
		if (so_pin.length != 8 || user_pin.length > 15 || try_cnt > 15 || dkek_num > 15){
			ret.status = HSM_ERR_CODE.hsm_err_invalid_parameter;
			return ret;
		}
		if(buffer.init){
			return await Module.ccall('initializeDevice', 'number', ['number', 'string', 'string', 'number', 'number', 'number', 'number'], [buffer.memory, so_pin, user_pin, try_cnt, dkek_num, is_transport, is_fingerprint], {async: true}).then(result => {
				if(result > 0){
					var resp = new Uint8Array(Module.HEAPU8.buffer, buffer.memory, result);
					ret.status = HSM_ERR_CODE.hsm_success;
					ret.resp = resp.slice(0);
					ret.data = resp.slice(0, result-2);
					var a = resp[result-2];
					var b = resp[result-1];
					ret.sw = a*256 + b;
				}				
				else{
					ret.status = HSM_ERR_CODE.hsm_err_ctap_error;
					ret.data = null;
					ret.sw = 0;
				}
				return ret;
			});
		}
		else{
			return ret;
		}
	}

    // use empty string input for default DKEK
    async import_dkek_share(dkek){
        var ret = {
            "status": HSM_ERR_CODE.hsm_err_undefined,
            "resp": null,
            "data": null,
            "sw": 0
        };
        if(buffer.init){
            return await Module.ccall('importDKEKShare', 'number', ['number', 'number', 'number', 'number'], [buffer.memory, null, 0 , 1], {async: true}).then(result => {
                if(result > 0){
                    var resp = new Uint8Array(Module.HEAPU8.buffer, buffer.memory, result);
                    ret.status = HSM_ERR_CODE.hsm_success;
                    ret.resp = resp.slice(0);
                    ret.data = resp.slice(0, result-2);
                    var a = resp[result-2];
                    var b = resp[result-1];
                    ret.sw = a*256 + b;
                }				
                else{
                    ret.status = HSM_ERR_CODE.hsm_err_ctap_error;
                    ret.data = null;
                    ret.sw = 0;
                }
                return ret;
            });
        }
        else{
            return ret;
        }
    }

    async query_dkek_status(){
        var ret = {
            "status": HSM_ERR_CODE.hsm_err_undefined,
            "resp": null,
            "data": null,
            "sw": 0
        };
        if(buffer.init){
            return await Module.ccall('queryDKEKStatus', 'number', ['number'], [buffer.memory], {async: true}).then(result => {
                if(result > 0){
                    var resp = new Uint8Array(Module.HEAPU8.buffer, buffer.memory, result);
                    ret.status = HSM_ERR_CODE.hsm_success;
                    ret.resp = resp.slice(0);
                    ret.data = resp.slice(0, result-2);
                    var a = resp[result-2];
                    var b = resp[result-1];
                    ret.sw = a*256 + b;
                }				
                else{
                    ret.status = HSM_ERR_CODE.hsm_err_ctap_error;
                    ret.data = null;
                    ret.sw = 0;
                }
                return ret;
            });
        }
        else{
            return ret;
        }
    }
*/
    /**
     * @returns {Array} Return a list of key's FID.
     */
    enumerateKey(){
        return this.seutil.enumerateObjects().then(response => {
            if (response.sw === HSM_STATUS_WORD.success) {
                let object = response.data;
                this._keyList.reset();
                for(let i = 2; i < object.length; i += 2){
                    let type = object[i];
                    if (type === (HSM_FILE_ID_PREFIX.private_key >>> 8)) {
                        let index = object[i+1];
                        if (0x01 <= index && index <= 0XFF)
                            this._keyList.element.push((type << 8) | index);
                    }
                }
                return this._keyList.element.sort();
            } else 
                return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        });
    }
    /**
     * 
     * @param {Number} keyFid Key FID or key index are both fine.
     * @returns {Object | Promise} Returns key object else promise.
     */
    async getKeyObject(keyFid){
        let keyIndex = keyFid & 0xFF;
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(keyIndex)) {
            return false;
        }

        let keyObject = {
            keyIndex: null,
            keyType: KX_ASYMMETRIC_KEY_TYPE.NA,
            isCertificate: false,
            publicKey: null,
            privateKeyInfo: null
        };

        try {
            keyObject.publicKey = await this.readPublicKey(keyIndex);
        
            keyObject.privateKeyInfo = await this.readPrivateKeyInfo(keyIndex);

            keyObject.isCertificate = asn1Parser.isCertificate(keyObject.publicKey);

            keyObject.keyType = asn1Parser.keyType(keyObject.isCertificate,
                                                keyObject.publicKey);
            keyObject.keyIndex = keyIndex;
            return keyObject;
        } catch(e) {
            console.error(e);
        }
    }
    /**
     * @param {Object} createKeyInfo Information for key generation
     * @returns {Boolean}
     */
    async createKey(createKeyInfo) {
        /*
            createKeyInfo = {
                keyIndex,
                type,
                config,
                label,
                uid
            }
         */
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        // check if the key index is valid
        if (0x01 <= createKeyInfo.keyIndex && createKeyInfo.keyIndex <= 0xFF) {
            // Key already exists at specified index
            if(this._keyList.isValid(createKeyInfo.keyIndex))
                return HSM_ERR_CODE.hsm_err_invalid_parameter;
        } else {
            for (let i = 0x01; i <= 0xFF; ++i) {
                if(!this._keyList.isValid(i)) {
                    createKeyInfo.keyIndex = i;
                    break;
                }
            }
        }
    	
        // to generate a key, the key, private_key_info and ee_certificate info need to be generated.
        let response;
        if(createKeyInfo.type === KX_ASYMMETRIC_KEY_TYPE.RSA) {
            response = await this.seutil.generateRsaAsymmetricKeyPair(createKeyInfo.keyIndex, createKeyInfo.config);
            if(response.sw === HSM_STATUS_WORD.success) {
                response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.ee_certificate + createKeyInfo.keyIndex, 0, response.data);
                response = await this.seutil.generateRsaPrivateKeyInfo(createKeyInfo.keyIndex, createKeyInfo.config, createKeyInfo.label, createKeyInfo.uid);
                response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.private_key_info + createKeyInfo.keyIndex, 0, response.data);
                // update key list
            } else {
                return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
            }
        } else if(createKeyInfo.type === KX_ASYMMETRIC_KEY_TYPE.ECC) {
            response = await this.seutil.generateEccAsymmetricKeyPair(createKeyInfo.keyIndex, createKeyInfo.config);
            if(response.sw === HSM_STATUS_WORD.success) {
                response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.ee_certificate + createKeyInfo.keyIndex, 0, response.data);
                response = await this.seutil.generateEccPrivateKeyInfo(createKeyInfo.keyIndex, createKeyInfo.config, createKeyInfo.label, createKeyInfo.uid);
                response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.private_key_info + createKeyInfo.keyIndex, 0, response.data);
                // update key list
            } else {
                return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
            }
        }
        
        if (response.sw === HSM_STATUS_WORD.success) {
            await this.enumerateKey();
            return await this.getKeyObject(createKeyInfo.keyIndex);
        }
        return true;
    }

    async deleteKey(keyIndex) {
        keyIndex = keyIndex & 0xFF;
        return this.seutil.deleteObject(HSM_FILE_ID_PREFIX.private_key + keyIndex).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return this.seutil.deleteObject(HSM_FILE_ID_PREFIX.private_key_info + keyIndex);
        }).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return this.seutil.deleteObject(HSM_FILE_ID_PREFIX.ee_certificate + keyIndex);
        }).then(response => {
            if (response.sw === HSM_STATUS_WORD.success) {
                this.enumerateKey();
                return true;
            }
            else
                return false;
        });
    }

    async readPublicKey(keyIndex) {
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(keyIndex)) {
            return false;
        }

        let response = HSM_RESP();

        // Read ee certicate
        let buff = [];
        let buff_len = 0;
        const readSize = 1024;

        // select EF before reading
        await this.seutil.selectObject(HSM_FILE_ID_PREFIX.ee_certificate + keyIndex);
        for (; response.sw !== HSM_STATUS_WORD.eof_reached;) {
            response = await this.seutil.readBinary(HSM_FILE_ID_PREFIX.ee_certificate + keyIndex, buff_len, readSize);
            if (response.sw !== HSM_STATUS_WORD.success && response.sw !== HSM_STATUS_WORD.eof_reached) {
                return Promise.reject(`${HSM_ERR_CODE.hsm_err_ctap_error}: Cannot read public key!`);
            }
            buff.push(response.data);
            buff_len += response.data.length;
        }
        let merge_buffer = new Uint8Array(buff_len);
        let merge_offset = 0;
        buff.forEach(snippet => {
            merge_buffer.set(snippet, merge_offset);
            merge_offset += snippet.length;
        })
        return merge_buffer.buffer;
    }
    /**
     * 
     * @param {number} keyIndex 
     * @param {arraybuffer} publicKey 
     * @returns 
     */
    async updatePublicKey(keyIndex, publicKey, isPrivate=false) {
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(keyIndex)) {
            return false;
        }

        let response = HSM_RESP();
        const object_file_prefix = (isPrivate)? HSM_FILE_ID_PREFIX.ee_certificate : HSM_FILE_ID_PREFIX.ca_certificate;

        let offset = 0;
        const updateSize = 1000;
        let slices = Math.floor(publicKey.byteLength / updateSize);
        for (let i = 0; i < slices; ++i) {
            response = await this.seutil.updateBinary(object_file_prefix + keyIndex,
                offset,
                new Uint8Array(publicKey.slice(offset, updateSize))
            );
            if (response.sw !== HSM_STATUS_WORD.success) {
                return Promise.reject("Error updating public key");
            }
            offset += updateSize;
        }
        // If there is still remainding data in the last slice
        if (publicKey.byteLength % updateSize) {
            response = await this.seutil.updateBinary(object_file_prefix + keyIndex,
                offset,
                new Uint8Array(publicKey.slice(offset))
            );
            if (response.sw !== HSM_STATUS_WORD.success) {
                return Promise.reject("Error updating public key");
            }
        }
        return true;
    }

    async readPrivateKeyInfo(keyIndex) {
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(keyIndex)) {
            return false;
        }

        let response = HSM_RESP();

        // Read private key info
        await this.seutil.selectObject(HSM_FILE_ID_PREFIX.private_key_info + keyIndex);
        response = await this.seutil.readBinary(HSM_FILE_ID_PREFIX.private_key_info + keyIndex, 0, 0);
        if (response.sw !== HSM_STATUS_WORD.success)
            return Promise.reject(`${HSM_ERR_CODE.hsm_err_undefined} Cannot read private key infomartion!`);
        return response.data.buffer;
    }
    /**
     * @param {Object} key Key object from `getKeyObject`
     * @param {*} data 
     * @returns 
     */
    async sign(key, data) {
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(key.keyIndex)) {
            return false;
        }

        let response;
        // if(key.isCertificate) {
            if(key.keyType === KX_ASYMMETRIC_KEY_TYPE.RSA) {
                response = await this.seutil.generateRsaSignature(key.keyIndex, data);
                if (response.sw === HSM_STATUS_WORD.success) {
                    return response.data;
                } else {
                    return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
                }
            } else if(key.keyType === KX_ASYMMETRIC_KEY_TYPE.ECC) {
                response = await this.seutil.generateEccSignature(key.keyIndex, data);
                if (response.sw === HSM_STATUS_WORD.success) {
                    return response.data;
                } else {
                    return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
                }
            }
        // } else {
        //     return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        // }
    }

    async rsaV1_5Sign(key, data) {
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(key.keyIndex)) {
            return false;
        }

        let response;
        if(key.keyType === KX_ASYMMETRIC_KEY_TYPE.RSA) {
            response = await this.seutil.generateRsav1_5Signature(key.keyIndex, new Uint8Array(data));
            if (response.sw === HSM_STATUS_WORD.success) {
                return response.data.buffer;
            }
        }
        return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
    }

    /**
     * @param {Object} key Key object from `getKeyObject`
     * @param {*} data 
     * @returns 
     */
    async decrypt(key, data) {
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(key.keyIndex)) {
            return false;
        }

        let response;
        // if(key.isCertificate) {
            if(key.keyType === KX_ASYMMETRIC_KEY_TYPE.RSA) {
                response = await this.seutil.generateRsaDecrypt(key.keyIndex, data);
                if (response.sw === HSM_STATUS_WORD.success) {
                    return response.data;
                } else {
                    return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
                }
            } else if(key.keyType === KX_ASYMMETRIC_KEY_TYPE.ECC) {
                response = await this.seutil.generateEccDecrypt(key.keyIndex, data);
                if (response.sw === HSM_STATUS_WORD.success) {
                    return response.data;
                } else {
                    return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
                }
            }
        // } else {
        //     return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        // }
    }

    /*async wrap_key(fid){
        var ret = {
            "status": HSM_ERR_CODE.hsm_err_undefined,
            "resp": null,
            "data": null,
            "sw": 0
        };
        if (typeof fid != 'number'){
            console.log("input parameter error")
            ret.status = HSM_ERR_CODE.hsm_err_invalid_parameter;
            return ret;
        }
        if(buffer.init){
            return await Module.ccall('wrapKey', 'number', ['number','number'], [buffer.memory, fid], {async: true}).then(result => {
                if(result > 0){
                    var resp = new Uint8Array(Module.HEAPU8.buffer, buffer.memory, result);
                    ret.status = HSM_ERR_CODE.hsm_success;
                    ret.resp = resp.slice(0);
                    ret.data = resp.slice(0, result-2);
                    var a = resp[result-2];
                    var b = resp[result-1];
                    ret.sw = a*256 + b;
                }				
                else{
                    ret.status = HSM_ERR_CODE.hsm_err_ctap_error;
                    ret.data = null;
                    ret.sw = 0;
                }
                return ret;
            });
        }
        else{
            return ret;
        }
    }

    async unwrap_key(fid, data){
        var ret = {
            "status": HSM_ERR_CODE.hsm_err_undefined,
            "resp": null,
            "data": null,
            "sw": 0
        };
        if (typeof fid != 'number' || !(data.constructor == Uint8Array)){
            console.log("input parameter error")
            ret.status = HSM_ERR_CODE.hsm_err_invalid_parameter;
            return ret;
        }
        if(buffer.init){
            var dataPtr = Module._malloc(data.length);
            Module.HEAPU8.set(data, dataPtr);
            
            return await Module.ccall('unWrapKey', 'number', ['number','number','number','number'], [buffer.memory, fid, dataPtr, data.length], {async: true}).then(result => {
                if(result > 0){
                    var resp = new Uint8Array(Module.HEAPU8.buffer, buffer.memory, result);
                    ret.status = HSM_ERR_CODE.hsm_success;
                    ret.resp = resp.slice(0);
                    ret.data = resp.slice(0, result-2);
                    var a = resp[result-2];
                    var b = resp[result-1];
                    ret.sw = a*256 + b;
                }				
                else{
                    ret.status = HSM_ERR_CODE.hsm_err_ctap_error;
                    ret.data = null;
                    ret.sw = 0;
                }
                Module._free(dataPtr);
                return ret;
            });
        }
        else{
            return ret;
        }
    }*/

    /**
     * @returns {Array} Return an a list of data container fid. 
     */
     enumerateData(){
        return this.seutil.enumerateObjects().then(response => {
            if (response.sw === HSM_STATUS_WORD.success) {
                let object = response.data;
                this._dataContainerList.reset();
                for(let i = 2; i < object.length; i += 2){
                    let type = object[i];
                    if (type === (HSM_FILE_ID_PREFIX.data_container_info >>> 8)) {
                        let index = object[i+1];
                        this._dataContainerList.element.push((type << 8) | index);
                    }
                }
                return this._dataContainerList.element.sort();
            } else 
                return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        });
    }
    /**
     * 
     * @param {Number} dataFid Pass either fid or index.
     * @returns 
     */
    async getDataObject(dataFid) {
        // dataObject = {
        //     containerFid
        //     dataFid: null,
        //     isPrivate: null,
        //     label: null,
        //     appInfo: null,
        //     oid: null,
        //     container: null,
        //     value: null
        // }
        let dataIndex = dataFid & 0xFF;
        if (this._dataContainerList.element === null) {
            await this.enumerateData();
        }
        if (!this._dataContainerList.isValid(dataIndex)) {
            return false;
        }

        // Get data object container
        let response = await this.seutil.readBinary(HSM_FILE_ID_PREFIX.data_container_info + dataIndex, 0, 0);
        let dataObject = asn1Parser.dataObjectInfo(response.data.buffer);
        dataObject.containerFid = HSM_FILE_ID_PREFIX.data_container_info + dataIndex;

        // Get data object value
        response = await this.seutil.readBinary(dataObject.dataFid, 0, 0);
        dataObject.value = response.data.buffer;

        return dataObject;
    }

    /**
     * 
     * @param {Object} dataInfo 
     * @returns Data Object.
     */
    async createData(dataInfo) {
        // dataInfo = {
        //     containerIndex: number
        //     isPrivate: boolean
        //     label: string
        //     appInfo: string
        //     oid: string
        //     value: arrayBuffer
        // }
        if (this._dataContainerList.element === null) {
            await this.enumerateData();
        }
        // check if the key index is valid
        if (0x00 <= dataInfo.containerIndex && dataInfo.containerIndex <= 0xFF) {
            // Key already exists at specified index
            if(this._dataContainerList.isValid(dataInfo.containerIndex))
                return HSM_ERR_CODE.hsm_err_invalid_parameter;
        } else {
            for (let i = 0x01; i <= 0xFF; ++i) {
                if(!this._dataContainerList.isValid(i)) {
                    dataInfo.containerIndex = i;
                    break;
                }
            }
        }

        let is_private = dataInfo.isPrivate;

        // Fill in data container info
        let response = await this.seutil.generateDataContainerInfo(dataInfo.containerIndex,
            is_private,
            dataInfo.label,
            dataInfo.appInfo,
            dataInfo.oid);
        response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.data_container_info + dataInfo.containerIndex, 0, response.data);
        
        // Fill in the value in the corresponding data block.
        let data = new Uint8Array(dataInfo.value);
        if(dataInfo.isPrivate)
            response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.confidential_data + dataInfo.containerIndex, 0, data);
        else
            response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.public_data + dataInfo.containerIndex, 0, data);
        
        if(response.sw === HSM_STATUS_WORD.success) {
            await this.enumerateData();
            return await this.getDataObject(dataInfo.containerIndex);
        }
        else
            return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
    }
    /**
     * 
     * @param {Number} containerIndex pass either fid or index.
     * @returns true.
     */
    async deleteData(containerIndex) {
        containerIndex = containerIndex & 0xFF;
        let response = await this.seutil.deleteObject(HSM_FILE_ID_PREFIX.data_container_info + containerIndex);
        if (response.sw !== HSM_STATUS_WORD.success)
            return false;
        
        await this.seutil.deleteObject(HSM_FILE_ID_PREFIX.confidential_data + containerIndex);
        await this.seutil.deleteObject(HSM_FILE_ID_PREFIX.public_data + containerIndex);

        await this.enumerateData();

        return true;
    }

    enumerateCert() {
        return this.seutil.enumerateObjects().then(response => {
            if (response.sw === HSM_STATUS_WORD.success) {
                let object = response.data;
                this._certList.reset();
                for(let i = 2; i < object.length; i += 2){
                    let type = object[i];
                    if (type === (HSM_FILE_ID_PREFIX.certificate_info >>> 8)) {
                        let index = object[i+1];
                        this._certList.element.push((type << 8) | index);
                    }
                }
                return this._certList.element.sort();
            } else 
                return Promise.reject(HSM_ERR_CODE.hsm_err_undefined);
        });
    }

    async getCertObject(certIndex) {
        // CertObject = {
        //     certIndex: null,
        //     label: null,
        //     id: null
        //     value: null
        // }
        certIndex = certIndex & 0xFF;
        if (this._certList.element === null) {
            await this.enumerateCert();
        }
        if (!this._certList.isValid(certIndex)) {
            return false;
        }

        // Get cert object container
        let response = await this.seutil.readBinary(HSM_FILE_ID_PREFIX.certificate_info + certIndex, 0, 0);
        let certObject = asn1Parser.certObjectInfo(response.data.buffer);

        // Get cert object value
        let buff = [];
        let buff_len = 0;
        const readSize = 900;
        await this.seutil.selectObject(HSM_FILE_ID_PREFIX.ca_certificate + certIndex);
        for (; response.sw !== HSM_STATUS_WORD.eof_reached;) {
            response = await this.seutil.readBinary(HSM_FILE_ID_PREFIX.ca_certificate + certIndex, buff_len, readSize);
            if (response.sw !== HSM_STATUS_WORD.success && response.sw !== HSM_STATUS_WORD.eof_reached) {
                return Promise.reject(HSM_ERR_CODE.hsm_err_ctap_error);
            }
            buff.push(response.data);
            buff_len += response.data.length;
        }
        let merge_buffer = new Uint8Array(buff_len);
        let merge_offset = 0;
        buff.forEach(snippet => {
            merge_buffer.set(snippet, merge_offset);
            merge_offset += snippet.length;
        })
        certObject.value = merge_buffer.buffer;

        certObject.certIndex = certIndex;
        return certObject;
    }
    /**
     * 
     * @param {Object} certInfo 
     * @type {number | undefined}   certIndex
     * @type {string}               label
     * @type {string}               id: SHA1 of public modulus.
     * @type {arraybuffer}          value
     * @returns 
     */
    async createCert(certInfo) {
        // certInfo = {
        //     certIndex: number
        //     label: string
        //     id: string
        //     value: arraybuffer
        // }
        if (this._certList.element === null) {
            await this.enumerateCert();
        }
        if (0x00 <= certInfo.certIndex && certInfo.certIndex <= 0xFF) {
            // Key already exists at specified index
            if(this._certList.isValid(certInfo.certIndex))
                return HSM_ERR_CODE.hsm_err_invalid_parameter;
        } else {
            for (let i = 0x01; i <= 0xFF; ++i) {
                if(!this._certList.isValid(i)) {
                    certInfo.certIndex = i;
                    break;
                }
            }
        }

        // Fill in cert container info
        let response = await this.seutil.generateCertContainerInfo(certInfo.certIndex,
            certInfo.label,
            array2hex(certInfo.id));
        response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.certificate_info + certInfo.certIndex, 0, response.data);
        
        // Fill in the value in the corresponding data block.
        let offset = 0;
        const updateSize = 900;
        let slices = Math.floor(certInfo.value.byteLength / updateSize);
        for (let i = 0; i < slices; ++i) {
            response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.ca_certificate + certInfo.certIndex,
                offset,
                new Uint8Array(certInfo.value.slice(offset, updateSize))
            );
            if (response.sw !== HSM_STATUS_WORD.success) {
                return Promise.reject("Error updating public key");
            }
            offset += updateSize;
        }
        // If there is still remainding data in the last slice
        if (certInfo.value.byteLength % updateSize) {
            response = await this.seutil.updateBinary(HSM_FILE_ID_PREFIX.ca_certificate + certInfo.certIndex,
                offset,
                new Uint8Array(certInfo.value.slice(offset))
            );
            if (response.sw !== HSM_STATUS_WORD.success) {
                return Promise.reject("Error updating public key");
            }
        }
        await this.enumerateCert();
        return await this.getCertObject(certInfo.certIndex);
    }

    async deleteCert(certIndex) {
        certIndex = certIndex & 0xFF;
        let response = await this.seutil.deleteObject(HSM_FILE_ID_PREFIX.certificate_info + certIndex);
        if (response.sw !== HSM_STATUS_WORD.success)
            return false;
        
        await this.seutil.deleteObject(HSM_FILE_ID_PREFIX.ca_certificate + certIndex);

        await this.enumerateCert();

        return true;
    }

    /**
     * By reason of login biometric auto is an vendor defined apdu command.
     * The status word when login success is "63CF" instead of 9000.
     * @returns {String | Promise} Returns promise if failed.
     */
	loginBiometricAuto(){
		return this.seutil.loginBiometricAuto().then(response => {
            // By reason of login biometric auto is an vendor defined apdu command.
            // The status word when login success is "63CF" instead of 9000.
            if (response.sw === 0x63CF) 
                return true;
            else
                return false;
        });
	}

    /**
     * 
     * @param {*} keyIndex 
     * @param {Object} certInfo keySize, label, id, common, email.
     * @param {arraybuffer} certData Read in certificate data.
     * @returns 
     */
    async importCert(keyIndex, certInfo, certData) {
        // let keyIndex = keyFid & 0xFF;
        if (this._keyList.element === null) {
            await this.enumerateKey();
        }
        if (!this._keyList.isValid(keyIndex)) {
            return false;
        }

        // update public key
        let result = await this.updatePublicKey(keyIndex, certData, true);
        if (result) {
            // update cert private key info
            result = await this.updateCertPrivateKeyInfo(keyIndex, certInfo);
        }
        return result;
    }

    /**
     * 
     * @param {number} keyIndex 
     * @param {Object} certInfo label and common both represent the common name
     * @type  {number} keySizeBits
     * @type  {string} label
     * @type  {arraybuffer} id
     * @type  {string} common
     * @type  {string} email
     */
    async updateCertPrivateKeyInfo(keyIndex, certInfo) {
        let response = await this.seutil.generateRsaCertPrivateKeyInfo(
            keyIndex, certInfo.keySizeBits, certInfo.label, new Uint8Array(certInfo.id), certInfo.common, certInfo.email);
        response = await this.seutil.updateBinary(
            HSM_FILE_ID_PREFIX.private_key_info + keyIndex, 0, response.data);
        
        if (response.sw === HSM_STATUS_WORD.success)
            return true;
        return false;
    }

    randomNumber(size){
        return this.seutil.generateRandomNumber(size).then(response => {
            if (response.sw === HSM_STATUS_WORD.success)
                return response.data.buffer;
            else
                return false;
        })
	
    }

    apduExchange(command) {
        return this.seutil.apduExchange(hex2array(command)).then(response => {
            return response
        });
    }
}

function HSM_RESP() {
    return {
        "status": HSM_ERR_CODE.hsm_err_undefined,
        "resp": null,
        "data": null,
        "sw": 0
    }
};
