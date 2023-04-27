import Web3 from "web3";
import KxToken from "./lib/src/KxToken";
import { pubToAddress, ethSign } from "kxeth-util";
import { ethers } from "ethers";

// NOTE: you need to make sure that kxToken object is built before using any kxToken method.
const kxToken = new KxToken();

// NOTE: you need to make sure that selectKeyObj exists before using any key related method (e.g. sign data, obtain address).
var selectKeyObj;

const initialKeyToken = () => {
  return new Promise((myResolve, myReject) => {
    kxToken
      .init()
      .then((result) => {
        // Result is either true or false
        console.log("init token result=", result);
        if (result) {
          myResolve(result);
        } else {
          myReject({ message: "Fail to connect to token." });
        }
      })
      .catch((error) => {
        console.log("init token error", error);
        myReject({ message: "Fail to connect to token." });
      });
  });
};

const loginToKeyTokenUsingFingerprint = () => {
  return new Promise((myResolve, myReject) => {
    kxToken
      .loginBiometricAuto()
      .then((result) => {
        // Result is either true or false
        console.log("loginBiometricAuto result=", result);
        if (result) {
          myResolve(result);
        } else {
          myReject({ message: "Fail to verify fingerprint." });
        }
      })
      .catch((error) => {
        console.log("login error", error);
        myReject({ message: "Fail to verify fingerprint." });
      });
  });
};

const getECCKeyList = () => {
  return new Promise((myResolve, myReject) => {
    kxToken
      .getObjectList("ECCPrivateKey")
      .then((result) => {
        console.log("getKeyList()", { result });
        myResolve(result);

        if (!result) {
          myReject({ message: "Fail to get key list." });
        }
      })
      .catch((error) => {
        console.log("getKeyList() getObjectList error", error);
        myReject({ message: "Fail to get key list." });
      });
  });
};

const obtainAddress = () => {
  let web3 = new Web3();
  let addressBytes = pubToAddress(new Uint8Array(selectKeyObj.publicKey));
  let address = web3.utils.bytesToHex(addressBytes).toLocaleLowerCase();
  return address;
};

const setSelectKeyObj = (key) => {
  selectKeyObj = key;
};

const toEthereumPrefixedMessage = (message) => {
  // NOTE: message length must get by turning into uft8Bytes first or Chinese characters will be converted incorrectly
  let prefixedMessage =
    "\x19Ethereum Signed Message:\n" +
    ethers.utils.toUtf8Bytes(message).length +
    message;
  return prefixedMessage;
};

const hexToarray = (string) => {
  if (string.slice(0, 2) === "0x") {
    string = string.slice(2, string.length);
  }
  if (string.length & 1) {
    throw new Error("Odd length hex string");
  }
  let arr = new Uint8Array(string.length / 2);
  var i;
  for (i = 0; i < string.length; i += 2) {
    arr[i / 2] = parseInt(string.slice(i, i + 2), 16);
  }
  return arr;
};

const signData = (message) => {
  console.log("signData() start, message=", message);
  let web3 = new Web3();
  let addressBytes = pubToAddress(new Uint8Array(selectKeyObj.publicKey));
  let address = web3.utils.bytesToHex(addressBytes).toLocaleLowerCase();
  // NOTE: if your message already contain ethereum prefixed, then you don't need to add the prefixed again.
  let toSignMessage = toEthereumPrefixedMessage(message);
  console.log("signData() toSignMessage=", toSignMessage);

  let messageBytes = ethers.utils.toUtf8Bytes(toSignMessage);
  let ecmsgHash = ethers.utils.keccak256(messageBytes);
  let ecmsgHashH2A = hexToarray(ecmsgHash);
  return new Promise((myResolve, myReject) => {
    selectKeyObj
      .SignRaw(ecmsgHashH2A)
      .then((signRawResult) => {
        let ethSignResult = ethSign(ecmsgHash, signRawResult, addressBytes);
        let rsvResult = {
          r: web3.utils.bytesToHex(ethSignResult.r).slice(2),
          s: web3.utils.bytesToHex(ethSignResult.s).slice(2),
          v: web3.utils.toHex(ethSignResult.v).slice(2),
          callerAddress: address,
        };
        console.log("signData() end, rsvResult=", rsvResult);
        myResolve(rsvResult);
      })
      .catch((err) => {
        console.error("signData() error", err);
        myReject({ message: "Sign data fail." });
      });
  });
};

export {
  initialKeyToken,
  loginToKeyTokenUsingFingerprint,
  getECCKeyList,
  setSelectKeyObj,
  signData,
  obtainAddress,
};
