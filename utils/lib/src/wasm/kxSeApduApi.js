import Module from './KXSEAPDUKit.js';

// General configuration for WebAssembly
const BUFFER_SIZE = 1024;
const noWebAuthnSupportStr = 'This browser does not support WebAuthn!';

// Error code of WebAssembly
const SEAPDUApi_errCode = new Map();
SEAPDUApi_errCode.set(-10, "WebAssembly buffer length exceeded");
SEAPDUApi_errCode.set(-50, "Function not implemented yet");
SEAPDUApi_errCode.set(-100, "Smart token failed to execute command");

// Error code of the HSM
const HSM_ERR_CODE = {
	hsm_err_undefined: -1,
    hsm_success: 0x9000,
    hsm_err_invalid_command: 0x01,
    // hsm_err_invalid_parameter: 0x02,
    hsm_err_invalid_parameter: 0x6a86,
    hsm_err_invalid_length: 0x03,
	hsm_err_not_initialized: 0x04,
	hsm_err_ctap_error: 0x10,
    hsm_err_ctap_not_logged_in: 0x6982
}

// Types and constants for the underlying library
const RSA_keySize = {
    "RSA1024": 1024,
    "RSA1536": 1536,
    "RSA2048": 2048
};

const ECC_keyType = {
    "secp256k1": 0,
    "secp256r1": 1
};

const defaultDKEK = new Uint8Array([
    0x9C, 0x39, 0x68, 0x5E, 0xB5, 0x6A, 0x6F, 0x19,
    0x84, 0xC7, 0x93, 0xD6, 0xF7, 0xA5, 0x48, 0xE8,
    0xF0, 0x45, 0x11, 0xB2, 0x6A, 0x59, 0xE8, 0x26,
    0x20, 0xF6, 0x82, 0x69, 0x5F, 0x8F, 0xB9, 0xDC
]);

function getErrorMessage(errCode) {
    return SEAPDUApi_errCode.has(errCode)? SEAPDUApi_errCode.get(errCode) : "Unknown error!";
}

function parseResponse(arrayBuffer, offset, length) {
    let resp = new Uint8Array(arrayBuffer, offset, length);
    let rData = resp.slice(0, -2);
    let swArr = resp.slice(-2);
    let swInt = (swArr[0] << 8) | swArr[1];
    return {
        response: resp,
        data: rData,
        sw: swInt
    };
}

export default class kxSeApduApi {
    constructor() {
        if (!window.PublicKeyCredential) {
            this._isInit = Promise.reject(noWebAuthnSupportStr);
        } else {
            this._isInit = new Module().then(wasmModule => {
                this._wasmModule = wasmModule;
                this._buffer = wasmModule.ccall('initialize', 'number', ['number'], [BUFFER_SIZE]);
                this._finalize = wasmModule.cwrap('finalize', 'number', ['number']);
                this._queryLoginStatus = wasmModule.cwrap('queryLoginStatus', 'number', []);
    
                /**
                 * Register a finalize registry to free up allocated memory in C code.
                 */
                // this.__registry = new FinalizationRegistry(heldValue => {
                //     this._finalize(heldValue);
                // });
                // this.__registry.register(this, this._buffer, this);
    
                return true;
            });
        }
    }

    destroy() {
        this._isInit.then(() => {
            // this.__registry.unregister(this);
            this._finalize(this._buffer);
        }).catch(error => {console.error(error)});
    }

    /**
     * Get the version of KXSEAPDUKit.
     * @returns A string representing the version of the underlying API.
     */
    version() {
        return this._isInit.then(() => {
            let versionInt =  this._wasmModule.ccall('version', 'number', [], []);
            let versionArray = [0, 0, 0];

            // The order of parsing version number is from back to forward.
            // rev > minor > major
            for (let index = 2; versionInt > 0; versionInt = versionInt >> 8, index--) {
                versionArray[index] = versionInt & 0xff;
            }

            let versionStr = versionArray.join(".");

            return versionStr;
        }).catch(error => {console.error(error)});
    }

    selectApplication() {
        return this._isInit.then(() => {
            return this._wasmModule.ccall('selectApplication', 'number', ['number'], [this._buffer], {async: true})
                .then((respLen) => {
                    if (respLen > 0)
                        return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                    else
                        return Promise.reject(getErrorMessage(respLen));
                });
        });
    }

    selectObject(fid) {
        return this._isInit.then(() => {
            if (typeof fid != 'number'){
                return Promise.reject(new TypeError('Invalid input type.'));
            }

            return this._wasmModule.ccall('selectObject', 'number', ['number', 'number'], [this._buffer, fid], {async: true})
                .then((respLen) => {
                    if (respLen > 0)
                        return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                    else
                        return Promise.reject(getErrorMessage(respLen));
                });
        });
    }

    // TODO: reconstruct the return value
    enumerateObjects() {
        return this._isInit.then(() => {
            return this._wasmModule.ccall('enumerateObjects', 'number', ['number'], [this._buffer], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    deleteObject(fid) {
        return this._isInit.then(() => {
            if (typeof fid != 'number'){
                return Promise.reject(new TypeError('Invalid input type.'));
            }

            return this._wasmModule.ccall('deleteObject', 'number', ['number', 'number'], [this._buffer, fid], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    /**
     * Login token with user pin.
     * 
     * User pin length must be between 1 and 15.
     * 
     * @param {*} userPin 
     * @returns 
     */
    verifyUserPin(userPin) {
        return this._isInit.then(() => {
            if (typeof userPin != 'string') {
                return Promise.reject(new TypeError('Input should be a string.'));
            }
            if(userPin.length < 1 || userPin.length > 15) {
                return Promise.reject(new RangeError('Invalid user pin length.'));
            }

            return this._wasmModule.ccall('verifyUserPin', 'number', ['number', 'string'], [this._buffer, userPin], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                        return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    verifyUserPinStatus() {
        return this._isInit.then(() => {
            return this._wasmModule.ccall('verifyUserPinStatus', 'number', ['number'], [this._buffer], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    verifySoPinStatus() {
        return this._isInit.then(() => {
            return this._wasmModule.ccall('verifySoPinStatus', 'number', ['number'], [this._buffer], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    resetRetryCounter(soPin) {
        return this._isInit.then(() => {
            if (typeof soPin != 'string') {
                return Promise.reject(new TypeError('Input should be a string.'));
            }
            if(soPin.length !== 8) {
                return Promise.reject(new RangeError('Invalid user pin length.'));
            }

            return this._wasmModule.ccall('resetRetryCounter', 'number', ['number', 'string'], [this._buffer, soPin], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    changeUserPin(userPin, newUserPin) {
        return this._isInit.then(() => {
            if (typeof userPin != 'string' || typeof newUserPin != 'string') {
                return Promise.reject(new TypeError('Input should be a string.'));
            }
            if ( (userPin.length < 1 || userPin.length > 15) &&
                 (newUserPin.length < 1 || newUserPin.length > 15) ) {
                return Promise.reject(new RangeError('Invalid input length.'));
            }

            return this._wasmModule.ccall('changeUserPin', 'number', ['number', 'string', 'string'], [this._buffer, userPin, newUserPin], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    changeSoPin(soPin, newSoPin) {
        return this._isInit.then(() => {
            if (typeof soPin != 'string' || typeof newSoPin != 'string') {
                return Promise.reject(new TypeError('Input should be a string.'));
            }
            if ( soPin.length !== 8 || newSoPin.length !== 8) {
                return Promise.reject(new RangeError('Invalid input length.'));
            }

            return this._wasmModule.ccall('changeSoPin', 'number', ['number', 'string', 'string'], [this._buffer, soPin, newSoPin], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    changeUserPinBySoPin(soPin, newUserPin) {
        return this._isInit.then(() => {
            if (typeof soPin != 'string' || typeof newUserPin != 'string') {
                return Promise.reject(new TypeError('Input should be a string.'));
            }
            if ( soPin.length !== 8 || 
                (newUserPin.length < 1 || newUserPin.length > 15) ) {
                return Promise.reject(new RangeError('Invalid input length.'));
            }

            return this._wasmModule.ccall('changeUserPinBySoPin', 'number', ['number', 'string', 'string'], [this._buffer, soPin, newUserPin], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    initializeDevice(soPin, newUserPin, isFingerprint) {
        return this._isInit.then(() => {
            if (typeof soPin != 'string' || typeof newUserPin != 'string' || typeof isFingerprint != 'boolean') {
                return Promise.reject(new TypeError('Input should be a string.'));
            }
            if ( soPin.length !== 8 || 
                (newUserPin.length < 1 || newUserPin.length > 15) ) {
                return Promise.reject(new RangeError('Invalid input length.'));
            }

            isFingerprint = isFingerprint? 1 : 0;

            return this._wasmModule.ccall('initializeDevice', 'number', ['number', 'string', 'string', 'number'], [this._buffer, soPin, newUserPin, isFingerprint], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }
    
    initializeDeviceToTransportPin(soPin, newUserPin, isFingerprint) {
        return this._isInit.then(() => {
            if (typeof soPin != 'string' || typeof newUserPin != 'string' || typeof isFingerprint != 'boolean') {
                return Promise.reject(new TypeError('Input should be a string.'));
            }
            if ( soPin.length !== 8 || 
                (newUserPin.length < 1 || newUserPin.length > 15) ) {
                return Promise.reject(new RangeError('Invalid input length.'));
            }

            isFingerprint = isFingerprint? 1 : 0;

            return this._wasmModule.ccall('initializeDeviceToTransportPin', 'number', ['number', 'string', 'string', 'number'], [this._buffer, soPin, newUserPin, isFingerprint], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    importDKEKShare(newDKEK) {
        return this._isInit.then(() => {
            if( !(newDKEK instanceof Uint8Array) ) {
                return Promise.reject(new TypeError('Input should be Uint8Array.'));
            }
            if(newDKEK.length !== defaultDKEK.length) {
                return Promise.reject(new RangeError('Invalid input length.'));
            }
            
            let dkekPtr = this._wasmModule._malloc(newDKEK.length * newDKEK.BYTES_PER_ELEMENT);
            this._wasmModule.HEAPU8.set(newDKEK, dkekPtr);
            return this._wasmModule.ccall('importDKEKShare', 'number', ['number', 'number', 'number'], [this._buffer, dkekPtr, dkekPtr.length], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            }).finally(() => {
                this._wasmModule._free(dkekPtr);
            });
        });
    }

    queryDKEKStatus() {
        return this._isInit.then(() => {
            return this._wasmModule.ccall('queryDKEKStatus', 'number', ['number'], [this._buffer], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    loginBiometricAuto() {
        return this._isInit.then(() => {
            return this._wasmModule.ccall('loginBiometricAuto', 'number', ['number'], [this._buffer], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    generateRsaAsymmetricKeyPair(index, keySize) {
        return this._isInit.then(() => {
            if (typeof index != 'number' || typeof keySize != 'number'){
                return Promise.reject(new TypeError('Input should be a number'));
            }

            return this._wasmModule.ccall('generateRsaAsymmetricKeyPair', 'number', ['number', 'number', 'number'], [this._buffer, index, keySize], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    generateEccAsymmetricKeyPair(index, keyType) {
        return this._isInit.then(() => {
            if (typeof index != 'number' || typeof keyType != 'number'){
                return Promise.reject(new TypeError('Input should be a number'));
            }

            return this._wasmModule.ccall('generateEccAsymmetricKeyPair', 'number', ['number', 'number', 'number'], [this._buffer, index, keyType], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    generateRsaPrivateKeyInfo(fid, keySizeInBits, label, id) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || typeof keySizeInBits != 'number'|| typeof label != 'string' || typeof id != 'string'  ){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            return this._wasmModule.ccall('generateRsaPrivateKeyInfo', 'number', 
                ['number', 'number', 'number', 'string', 'string'], [this._buffer, fid, keySizeInBits, label, id], {async: true})
            .then((respLen) => {
                if (respLen > 0) {
                    // Special case of APDU command, since this command was not passed into the SE.
                    let resp = new Uint8Array(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                    return {
                        response: resp,
                        data: resp,
                        sw: 0
                    };
                }
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    generateEccPrivateKeyInfo(fid, keySizeInBits, label, id) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || typeof keySizeInBits != 'number'|| typeof label != 'string' || typeof id != 'string'  ){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            return this._wasmModule.ccall('generateEccPrivateKeyInfo', 'number', 
                ['number', 'number', 'number', 'string', 'string'], [this._buffer, fid, keySizeInBits, label, id], {async: true})
            .then((respLen) => {
                if (respLen > 0) {
                    // Special case of APDU command, since this command was not passed into the SE.
                    let resp = new Uint8Array(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                    return {
                        response: resp,
                        data: resp,
                        sw: 0
                    };
                }
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    generateDataContainerInfo(fid, isPrivate, label, appInfo, oid) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || typeof isPrivate != 'boolean' || typeof label != 'string' || typeof appInfo != 'string' || typeof oid != 'string'){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            isPrivate = isPrivate? 1 : 0;

            return this._wasmModule.ccall('generateDataContainerInfo', 'number', 
                ['number', 'number', 'number', 'string', 'string', 'string'], [this._buffer, fid, isPrivate, label, appInfo, oid], {async: true})
            .then((respLen) => {
                if (respLen > 0) {
                      // Special case of APDU command, since this command was not passed into the SE.
                      let resp = new Uint8Array(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                      return {
                          response: resp,
                          data: resp,
                          sw: 0
                      };
                }
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    generateCertContainerInfo(fid, label, id) {
        if (typeof fid != 'number' || typeof label != 'string' || typeof id != 'string'){
            return Promise.reject(new TypeError('Invalid input type'));
        }

        return this._isInit.then(() => {
            return this._wasmModule.ccall('generateCertContainerInfo', 'number', 
                ['number', 'number', 'string', 'string'], [this._buffer, fid, label, id], {async: true})
            .then((respLen) => {
                if (respLen > 0) {
                    // Special case of APDU command, since this command was not passed into the SE.
                    let resp = new Uint8Array(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                    return {
                        response: resp,
                        data: resp,
                        sw: 0
                    };
                }
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    generateRsaCertPrivateKeyInfo(fid, keySizeInBits, label, id, common, email) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || typeof keySizeInBits != 'number' || typeof label != 'string' || typeof id != 'string' || typeof common != 'string' || typeof email != 'string'){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            return this._wasmModule.ccall('generateRsaCertPrivateKeyInfo', 'number', 
                ['number', 'number', 'number', 'string', 'string', 'string', 'string'],
                [this._buffer, fid, keySizeInBits, label, id, common, email], {async: true})
            .then((respLen) => {
                if (respLen > 0) {
                    // Special case of APDU command, since this command was not passed into the SE.
                    let resp = new Uint8Array(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                    return {
                        response: resp,
                        data: resp,
                        sw: 0
                    };
                }
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    // TODO: don't let user pass dataSize
    // generateRsaSignature(fid, data, dataSize) {
    generateRsaSignature(fid, data) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || !(data instanceof Uint8Array)){
                return Promise.reject(new TypeError('Invalid input type'));
            }
            
            let dataPtr = this._wasmModule._malloc(data.length * data.BYTES_PER_ELEMENT);
            this._wasmModule.HEAPU8.set(data, dataPtr);
            return this._wasmModule.ccall('generateRsaSignature', 'number', ['number', 'number', 'number', 'number'],
                [this._buffer, fid, dataPtr, data.length], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            }).finally(() => {
                this._wasmModule._free(dataPtr);
            });
        });
    }

    // TODO: don't let user pass dataSize
    // generateEccSignature(fid, data, dataSize) {
    generateEccSignature(fid, data) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || !(data instanceof Uint8Array)){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            let dataPtr = this._wasmModule._malloc(data.length * data.BYTES_PER_ELEMENT);
            this._wasmModule.HEAPU8.set(data, dataPtr);
            return this._wasmModule.ccall('generateEccSignature', 'number', ['number', 'number', 'number', 'number'],
                [this._buffer, fid, dataPtr, data.length], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            }).finally(() => {
                this._wasmModule._free(dataPtr);
            });
        });
    }

    // TODO: don't let user pass dataSize
    // generateRsaDecrypt(fid, data, dataSize) {
    generateRsaDecrypt(fid, data) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || !(data instanceof Uint8Array)){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            let dataPtr = this._wasmModule._malloc(data.length * data.BYTES_PER_ELEMENT);
            this._wasmModule.HEAPU8.set(data, dataPtr);
            return this._wasmModule.ccall('generateRsaDecrypt', 'number', ['number', 'number', 'number', 'number'],
                [this._buffer, fid, dataPtr, data.length], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            }).finally(() => {
                this._wasmModule._free(dataPtr);
            });
        });
    }

    // TODO: don't let user pass dataSize
    // generateECDH(fid, publicKey, publicKeySize) {
    generateECDH(fid, publicKey) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || !(publicKey instanceof Uint8Array)){
                return Promise.reject(new TypeError('Invalid input type'));
            }
            
            let dataPtr = this._wasmModule._malloc(publicKey.length * publicKey.BYTES_PER_ELEMENT);
            this._wasmModule.HEAPU8.set(publicKey, dataPtr);
            return this._wasmModule.ccall('generateECDH', 'number', ['number', 'number', 'number', 'number'],
                [this._buffer, fid, dataPtr, publicKey.length], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            }).finally(() => {
                this._wasmModule._free(dataPtr);
            });
        });
    }

    readBinary(fid, readOffset, readSize) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || typeof readOffset != 'number' || typeof readSize != 'number' ){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            return this._wasmModule.ccall('readBinary', 'number', ['number', 'number', 'number', 'number'],
                [this._buffer, fid, readOffset, readSize], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    // TODO: don't let user pass dataSize
    // updateBinary(fid, offset, data, dataSize) {
    updateBinary(fid, offset, data) {
        return this._isInit.then(() => {
            if (typeof fid != 'number' || typeof offset != 'number' || !(data instanceof Uint8Array)){
                return Promise.reject(new TypeError('Invalid input type'));
            }

            let dataPtr = this._wasmModule._malloc(data.length * data.BYTES_PER_ELEMENT);
            this._wasmModule.HEAPU8.set(data, dataPtr);
            return this._wasmModule.ccall('updateBinary', 'number', ['number', 'number', 'number', 'number', 'number'],
                [this._buffer, fid, offset, dataPtr, data.length], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            }).finally(() => {
                this._wasmModule._free(dataPtr);
            });
        });
    }

    generateRandom(randomSize) {
        return this._isInit.then(() => {
            if(typeof randomSize != 'number') {
                return Promise.reject(new TypeError('Invalid input type'));
            }
            if(randomSize < 0) {
                return Promise.reject(new RangeError('Invalid input length'));
            }

            return this._wasmModule.ccall('generateRandom', 'number', ['number', 'number'],
                [this._buffer, randomSize], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }

    apduExchange(commands) {
        return this._isInit.then(() => {
            this._wasmModule.HEAPU8.set(commands, this._buffer);
            return this._wasmModule.ccall('apduExchange', 'number', ['number', 'number'],
                [this._buffer, commands.length], {async: true})
            .then((respLen) => {
                if (respLen > 0)
                    return parseResponse(this._wasmModule.HEAPU8.buffer, this._buffer, respLen);
                else
                    return Promise.reject(getErrorMessage(respLen));
            });
        });
    }
}

export { ECC_keyType,
         RSA_keySize,
         defaultDKEK,
         HSM_ERR_CODE };