#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <emscripten/emscripten.h>
#include "KXAPDUKit.h"
#include "KXSEAPDUDef.h"    // consider not to expose this header file.
#include "KXUtilLibDef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BUFFER_SIZE 1024

#define BUFFER_LENGTH_EXCEED        -10
#define FUNCTION_NOT_IMPLEMENTED    -50
#define CTAP_SEND_COMMAND_FAILED    -100

const unsigned char default_dkek[] = {
    0x9C, 0x39, 0x68, 0x5E, 0xB5, 0x6A, 0x6F, 0x19,
    0x84, 0xC7, 0x93, 0xD6, 0xF7, 0xA5, 0x48, 0xE8,
    0xF0, 0x45, 0x11, 0xB2, 0x6A, 0x59, 0xE8, 0x26,
    0x20, 0xF6, 0x82, 0x69, 0x5F, 0x8F, 0xB9, 0xDC
};

/**
 * @brief Passing APDU command to Smart Token through CTAP .
 * 
 * We wrap our APDU command into CTAP protocol to enable communicating
 * between the web browsers and Smart token.
 * 
 * @param data      Pointer of the apdu command memory.
 * @param size      Length of the apdu command.
 * @param timeout   How long will the pipeline will be timeout.
 * @return          When success returns an integer indicating the length of the reponse.
 *                  Else, returns -100 indicating failed to send APDU command.
 */
EM_JS(int, ctap_apdu_exchange, (uint8_t *data, uint16_t size, uint32_t timeout), {
    return Asyncify.handleAsync(() => {
        let apdu = HEAPU8.subarray(data, data + size);
        let challenge = self.crypto.getRandomValues(new Uint8Array(32));

        // package APDU into keyhandle
        // magic number: KXAPDU
        let pkg_keyhandle = new Uint8Array(size + 6);
        pkg_keyhandle[0] = 0x4B;
        pkg_keyhandle[1] = 0x58;
        pkg_keyhandle[2] = 0x41;
        pkg_keyhandle[3] = 0x50;
        pkg_keyhandle[4] = 0x44;
        pkg_keyhandle[5] = 0x55;
        pkg_keyhandle.set(apdu, 6);

        let request_options = {
            challenge: challenge,
            allowCredentials: [{
                id: pkg_keyhandle,
                type: 'public-key'
            }],
            timeout: 60000,
            userVerification: 'discouraged'
        };

        return navigator.credentials.get({publicKey: request_options})
            .then(assertion => {
                let signature = new Uint8Array(assertion.response.signature);
                HEAPU8.set(signature, data);
                // console.log("signature:", signature);
                return signature.length;
            }).catch(error => {
                console.log("THE ERROR:", error);
                HEAPU8.set(new Uint8Array([0x90, 0x00]), data);
                // ctap send command failed
                return -100;
            });
    });
});

IKXSEAPDU *KXSEAPDU = nullptr;

EMSCRIPTEN_KEEPALIVE
int version() {
    return KXAPDUKitGetVersion();
}

EMSCRIPTEN_KEEPALIVE
uint8_t *initialize(int size) {
    KXSEAPDU = CreateKXSEAPDU();
    return (uint8_t*)malloc(size * sizeof(uint8_t));
}

EMSCRIPTEN_KEEPALIVE
void finalize(uint8_t *buf) {
    ReleaseKXSEAPDU(KXSEAPDU);
    free(buf);
}

EMSCRIPTEN_KEEPALIVE
// TODO: Add SE info
int selectApplication(uint8_t *buf) {
    KXApplicationNode application_node;
    application_node.AID = ST_AID;
    application_node.AID_SIZE = sizeof(ST_AID);
    
    KXAPDUNode apdu_node;
    KXSEAPDU->SelectApplication(application_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int selectObject(uint8_t *buf, int fid) {
    KXFileNode file_node;
    file_node.FID[0] = MSB(fid);
    file_node.FID[1] = LSB(fid);

    KXAPDUNode apdu_node;
    KXSEAPDU->SelectObject(file_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int enumerateObjects(uint8_t *buf) {
    KXAPDUNode apdu_node;
    KXSEAPDU->EnumerateObjects(apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

/**
 * @brief Why do we even need this? It just creates an empty object.
 * 
 * @param buf 
 * @return EMSCRIPTEN_KEEPALIVE 
 */
EMSCRIPTEN_KEEPALIVE
int createObject(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int deleteObject(uint8_t *buf, int fid) {
    KXFileNode file_node;
    file_node.FID[0] = MSB(fid);
    file_node.FID[1] = LSB(fid);

    KXAPDUNode apdu_node;
    KXSEAPDU->DeleteObject(file_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int verifyUserPin(uint8_t *buf, char *user_pincode) {
    KXPinNode user_pin;
    user_pin.pincode = (unsigned char*)user_pincode;
    user_pin.pincode_length = strlen(user_pincode);

    KXAPDUNode apdu_node;
    KXSEAPDU->VerifyUserPin(user_pin, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
// TODO: Add error handling
int verifyUserPinStatus(uint8_t *buf) {
    KXAPDUNode apdu_node;
    KXSEAPDU->VerifyUserPinStatus(apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
// TODO: Add error handling
int verifySoPinStatus(uint8_t *buf) {
    KXAPDUNode apdu_node;
    KXSEAPDU->VerifySoPinStatus(apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int resetRetryCounter(uint8_t *buf, char *so_pincode) {
    KXPinNode so_pin;
    so_pin.pincode = (unsigned char*)so_pincode;
    so_pin.pincode_length = strlen(so_pincode);

    KXAPDUNode apdu_node;
    KXSEAPDU->ResetRetryCounter(so_pin, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int changeUserPin(uint8_t *buf, char *user_pincode, char *new_user_pincode) {
    KXPinNode user_pin;
    user_pin.pincode = (unsigned char*)user_pincode;
    user_pin.pincode_length = strlen(user_pincode);

    KXPinNode new_user_pin;
    new_user_pin.pincode = (unsigned char*)new_user_pincode;
    new_user_pin.pincode_length = strlen(new_user_pincode);

    KXAPDUNode apdu_node;
    KXSEAPDU->ChangeUserPin(user_pin, new_user_pin, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int changeSoPin(uint8_t *buf, char *so_pincode, char *new_so_pincode) {
    KXPinNode so_pin;
    so_pin.pincode = (unsigned char*)so_pincode;
    so_pin.pincode_length = strlen(so_pincode);

    KXPinNode new_so_pin;
    new_so_pin.pincode = (unsigned char*)new_so_pincode;
    new_so_pin.pincode_length = strlen(new_so_pincode);

    KXAPDUNode apdu_node;
    KXSEAPDU->ChangeSoPin(so_pin, new_so_pin, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int changeUserPinBySoPin(uint8_t *buf, char *so_pincode, char *new_user_pincode) {
    KXPinNode so_pin;
    so_pin.pincode = (unsigned char*)so_pincode;
    so_pin.pincode_length = strlen(so_pincode);

    KXPinNode new_user_pin;
    new_user_pin.pincode = (unsigned char*)new_user_pincode;
    new_user_pin.pincode_length = strlen(new_user_pincode);

    KXAPDUNode apdu_node;
    KXSEAPDU->ChangeUserPinBySoPin(so_pin, new_user_pin, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

/**
 * @brief Initialize device
 * 
 * @note: KX701 did not has NT applet inside it, so we need to remove the initialization code for
 * biometric data maatching. I'm adding this functionality here for convenience, but maybe some day.
 * We'll have to add it in KXSEAPDU. Steven, 27 Apr, 2022.
 * 
 * @param buf 
 * @param so_pincode 
 * @param new_user_pincode 
 * @param is_fingerprint_exists 
 * @return EMSCRIPTEN_KEEPALIVE 
 */
EMSCRIPTEN_KEEPALIVE
int initializeDevice(uint8_t *buf, char *so_pincode, char *new_user_pincode, int is_fingerprint_exists) {
    KXPinNode so_pin;
    so_pin.pincode = (unsigned char*)so_pincode;
    so_pin.pincode_length = strlen(so_pincode);

    KXPinNode new_user_pin;
    new_user_pin.pincode = (unsigned char*)new_user_pincode;
    new_user_pin.pincode_length = strlen(new_user_pincode);

    KXAPDUNode apdu_node;
    KXSEAPDU->InitializeDevice(so_pin, new_user_pin, apdu_node);

    if (is_fingerprint_exists == 1) {
        apdu_node.apdu_data[4] = 0x1C;
        apdu_node.apdu_data_size = 33;
    }

    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

/**
 * @brief Initialize device to tranport pin mode.
 * 
 * When device is in transport pin mode. The only action user can do is initialize device.
 * 
 * @note As above. Steven. 27 Apr, 2022.
 * 
 * @param buf 
 * @param so_pincode 
 * @param new_user_pincode 
 * @param is_fingerprint_exists 
 * @return EMSCRIPTEN_KEEPALIVE 
 */
EMSCRIPTEN_KEEPALIVE
int initializeDeviceToTransportPin(uint8_t *buf, char *so_pincode, char *new_user_pincode, int is_fingerprint_exists) {
    KXPinNode so_pin;
    so_pin.pincode = (unsigned char*)so_pincode;
    so_pin.pincode_length = strlen(so_pincode);

    KXPinNode new_user_pin;
    new_user_pin.pincode = (unsigned char*)new_user_pincode;
    new_user_pin.pincode_length = strlen(new_user_pincode);

    KXAPDUNode apdu_node;
    KXSEAPDU->InitializeDeviceToTransportPin(so_pin, new_user_pin, apdu_node);

    if (is_fingerprint_exists == 1) {
        apdu_node.apdu_data[4] = 0x1C;
        apdu_node.apdu_data_size = 33;
    }

    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int importDKEKShare(uint8_t *buf, uint8_t *new_dkek, int dkek_len) {
    KXDKEKNode new_dkek_node;
    memcpy(new_dkek_node.DKEK, new_dkek, dkek_len);

    KXAPDUNode apdu_node;
    KXSEAPDU->ImportDKEKShare(new_dkek_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int queryDKEKStatus(uint8_t *buf) {
    KXAPDUNode apdu_node;
    KXSEAPDU->QueryDKEKStatus(apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

/**
 * @brief Login fingerprint
 * 
 * This is a special APDU command for CTAP APDU exchange to login Smart token
 * with fingerprint. This command does not exist in the APDUKit.
 * 
 * @param buf A common buffer to store data for C and JavaScript.
 * @return An integer indicating the return size of the command. 
 */
EMSCRIPTEN_KEEPALIVE
int loginBiometricAuto(uint8_t *buf) {
    unsigned char _cmd_data[] = {CLA_00, INS_VERIFY, 0x00, 0x81, 0x00};

    size_t cmd_size = sizeof(_cmd_data);
    memcpy(buf, _cmd_data, cmd_size);

    int respLen = ctap_apdu_exchange(buf, cmd_size, 6000);
    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int verifyBiometric(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int verifyBiometricStatus(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int updateBiometric(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int unblockBiometric(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int readBiometricBIGT(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int updateBiometricBIGT(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int deleteBiometricBIGT(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int updateBiometricBIGTnTemplate(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int delete2BiometricBIGT(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int generateRsaAsymmetricKeyPair(uint8_t *buf, int index, int key_size_in_bits) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(index);
    key_node.FID[1] = LSB(index);

    // Key size is the only one that matters when generating asymmetric key pair
    KXKeyPropNode key_prop_node;
    key_prop_node.key_size_in_bits = key_size_in_bits;

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateRsaAsymmetricKeyPair(key_node, key_prop_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int generateEccAsymmetricKeyPair(uint8_t *buf, int index, int key_type) {
    printf("key type=%d", key_type);
    KXKeyNode key_node;
    key_node.FID[0] = MSB(index);
    key_node.FID[1] = LSB(index);

    // Key size is the only one that matters when generating asymmetric key pair
    KXKeyPropNode key_prop_node;
    key_prop_node.key_size_in_bits = key_type;

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateEccAsymmetricKeyPair(key_node, key_prop_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

/**
 * @brief Generate RSA key private key info in ASN1 format.
 * 
 * This function did not send commands into token.
 * Instead, we use this function to generate an ASN1 file and
 * call UpdateBinary to write it into the corresponding FID.
 * 
 * @param buf 
 * @param fid 
 * @param key_size_in_bits 
 * @param label 
 * @param id 
 * @return EMSCRIPTEN_KEEPALIVE 
 */
EMSCRIPTEN_KEEPALIVE
int generateRsaPrivateKeyInfo(uint8_t *buf, int fid, int key_size_in_bits, char *label, char *id) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(fid);
    key_node.FID[1] = LSB(fid);

    KXKeyPropNode key_prop_node;
    key_prop_node.key_size_in_bits = (unsigned int)key_size_in_bits;
    key_prop_node.label = (unsigned char*)label;
    key_prop_node.label_length = strlen(label);
    key_prop_node.id = (unsigned char*)id;
    key_prop_node.id_length = strlen(id);

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateRsaPrivateKeyInfo(key_node, key_prop_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    return apdu_node.apdu_data_size;
}

/**
 * @brief Generate ECC key private key info in ASN1 format.
 * 
 * This function did not send commands into token.
 * Instead, we use this function to generate an ASN1 file and
 * call UpdateBinary to write it into the corresponding FID.
 * 
 * @param buf 
 * @param fid 
 * @param key_size_in_bits 
 * @param label 
 * @param id 
 * @return EMSCRIPTEN_KEEPALIVE 
 */
EMSCRIPTEN_KEEPALIVE
int generateEccPrivateKeyInfo(uint8_t *buf, int fid, int key_size_in_bits, char *label, char *id) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(fid);
    key_node.FID[1] = LSB(fid);

    KXKeyPropNode key_prop_node;
    key_prop_node.key_size_in_bits = key_size_in_bits;
    key_prop_node.label = (unsigned char*)label;
    key_prop_node.label_length = strlen(label);
    key_prop_node.id = (unsigned char*)id;
    key_prop_node.id_length = strlen(id);

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateEccPrivateKeyInfo(key_node, key_prop_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    return apdu_node.apdu_data_size;
}

// TODO: maybe change is_private type to boolean?
EMSCRIPTEN_KEEPALIVE
int generateDataContainerInfo(uint8_t *buf, int fid, int is_private, char *label, char *appinfo, char *oid) {
    printf("Data Container Info");
    KXDataNode data_node;
    data_node.FID[0] = MSB(fid);
    data_node.FID[1] = LSB(fid);

    KXDataPropNode data_prop_node;
    data_prop_node.is_private = is_private;
    data_prop_node.label = (unsigned char*)label;
    data_prop_node.label_length = strlen(label);
    data_prop_node.appinfo = (unsigned char*)appinfo;
    data_prop_node.appinfo_length = strlen(appinfo);
    data_prop_node.oid = (unsigned char*)oid;
    data_prop_node.oid_length = strlen(oid);

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateDataContainerInfo(data_node, data_prop_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    return apdu_node.apdu_data_size;
}

EMSCRIPTEN_KEEPALIVE
int generateCertContainerInfo(uint8_t *buf, int fid, char *label, char *id) {
    KXCertNode cert_node;
    cert_node.FID[0] = MSB(fid);
    cert_node.FID[1] = LSB(fid);
    
    KXCertPropNode cert_prop_node;
    cert_prop_node.label = (unsigned char*)label;
    cert_prop_node.label_length = strlen(label);
    cert_prop_node.id = (unsigned char*)id;
    cert_prop_node.id_length = strlen(id);

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateCertContainerInfo(cert_node, cert_prop_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    return apdu_node.apdu_data_size;
}

/**
 * @brief This command only generate object for RSA key.
 * 
 * @param buf 
 * @param fid 
 * @param key_size_in_bits 
 * @param label 
 * @param id 
 * @param common 
 * @param email 
 * @return EMSCRIPTEN_KEEPALIVE 
 */
EMSCRIPTEN_KEEPALIVE
int generateRsaCertPrivateKeyInfo(uint8_t *buf, int fid, int key_size_in_bits, char *label, char *id, char *common, char *email) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(fid);
    key_node.FID[1] = LSB(fid);

    KXKeyCertPropNode cert_prop_node;
    cert_prop_node.key_size_in_bits = key_size_in_bits;
    cert_prop_node.label = (unsigned char*)label;
    cert_prop_node.label_length = strlen(label);
    cert_prop_node.id = (unsigned char*)id;
    cert_prop_node.id_length = strlen(id);
    cert_prop_node.common = (unsigned char*)common;
    cert_prop_node.common_length = strlen(common);
    cert_prop_node.email = (unsigned char*)email;
    cert_prop_node.email_length = strlen(email);

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateCertPrivateKeyInfo(key_node, cert_prop_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    return apdu_node.apdu_data_size;
}

// NOTE: In KXSmartTokenSdk, this function is only available for RSA key.
// I've add a new funtion called generateRsaCertPrivateKeyInfo just to make clear which
// type of key can this function supports.
// We could consider to remove or rename this function probably.
EMSCRIPTEN_KEEPALIVE
int generateCertPrivateKeyInfo(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int generateRsaSignature(uint8_t *buf, int fid, uint8_t *data, int data_len) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(fid);
    key_node.FID[1] = LSB(fid);

    KXInputNode input_node;
    input_node.input_data = (unsigned char*)data;
    input_node.input_data_size = (unsigned int)data_len;

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateRsaSignature(key_node, input_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int generateEccSignature(uint8_t *buf, int fid, uint8_t *data, int data_len) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(fid);
    key_node.FID[1] = LSB(fid);

    KXInputNode input_node;
    input_node.input_data = (unsigned char*)data;
    input_node.input_data_size = (unsigned int)data_len;

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateEccSignature(key_node, input_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int generateRsaDecrypt(uint8_t *buf, int fid, uint8_t *data, int data_len) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(fid);
    key_node.FID[1] = LSB(fid);

    KXInputNode input_node;
    input_node.input_data = (unsigned char*)data;
    input_node.input_data_size = (unsigned int)data_len;

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateRsaDecrypt(key_node, input_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

/**
 * @brief Generates a shared secret points using ECDH
 * 
 * @param buf 
 * @param fid 
 * @param public_key Public key of the sender. Concatenation of '04' || x || y point coordinates of ECC public key.
 * @param public_key_len 
 * @return EMSCRIPTEN_KEEPALIVE 
 */
EMSCRIPTEN_KEEPALIVE
int generateECDH(uint8_t *buf, int fid, uint8_t *public_key, int public_key_len) {
    KXKeyNode key_node;
    key_node.FID[0] = MSB(fid);
    key_node.FID[1] = LSB(fid);

    KXInputNode input_node;
    input_node.input_data = (unsigned char*)public_key;
    input_node.input_data_size = (unsigned int)public_key_len;

    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateEccDecrypt(key_node, input_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int wrapKey(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

EMSCRIPTEN_KEEPALIVE
int unwrapKey(uint8_t *buf) {
    return FUNCTION_NOT_IMPLEMENTED;
}

// todo: add max buffer checking
// maybe in ctap_aodu_exchange?
EMSCRIPTEN_KEEPALIVE
int readBinary(uint8_t *buf, int fid, int read_offset, int read_size) {
    KXReadNode read_node;
    read_node.FID[0] = MSB(fid);
    read_node.FID[1] = LSB(fid);
    read_node.read_offset = (unsigned int)read_offset;
    read_node.read_data_size = (read_size < KX_APDU_EXTEND_RW_SIZE) ? read_size : KX_APDU_EXTEND_RW_SIZE;

    KXAPDUNode apdu_node;
    KXSEAPDU->ReadBinary(read_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int updateBinary(uint8_t *buf, int fid, int offset, uint8_t *data, int data_size) {
    KXUpdateNode update_node;
    update_node.FID[0] = MSB(fid);
    update_node.FID[1] = LSB(fid);

    update_node.update_data = (unsigned char*)data;
    update_node.update_data_size = (unsigned int)data_size;
    update_node.update_offset = (unsigned int)offset;


    KXAPDUNode apdu_node;
    KXSEAPDU->UpdateBinary(update_node, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int generateRandom(uint8_t *buf, int size) {
    KXAPDUNode apdu_node;
    KXSEAPDU->GenerateRandom((unsigned int)size, apdu_node);
    memcpy(buf, apdu_node.apdu_data, apdu_node.apdu_data_size);

    int respLen = ctap_apdu_exchange(buf, apdu_node.apdu_data_size, 6000);

    return respLen;
}

EMSCRIPTEN_KEEPALIVE
int apduExchange(uint8_t *buf, int size) {
    return ctap_apdu_exchange(buf, size, 6000);
}

#ifdef __cplusplus
}
#endif
