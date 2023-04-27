import { Button, TextField, Typography } from "@mui/material";
import { Box } from "@mui/system";
import { useState } from "react";
import ConnectionSteps from "../components/ConnectionSteps";


const SignYourData = ({ onSignClick, signResult, kxUtil }) => {
  const [message, setMessage] = useState("");
  return (
    <>
      <TextField
        id="message-input"
        name="keys"
        value={message}
        variant="outlined"
        size="small"
        color="secondary"
        placeholder="Enter to sign message"
        onChange={(event) => {
          setMessage(event.target.value);
        }}
        sx={{ width: "50%" }}
      />
      <Button
        variant="contained"
        onClick={() => onSignClick(message, kxUtil)}
        sx={{ ml: 1 }}
      >
        Sign Data
      </Button>
      {signResult && (
        <>
          <Box mt={2} sx={{ wordBreak: "break-all" }}>
            Sign Result:
            <br />
            <br />
            {JSON.stringify(signResult)}
          </Box>
          <Typography
            component="a"
            href={`https://bns.itrustmachines.com/tool/signature?r=${signResult.r}&s=${signResult.s}&v=${signResult.v}&message=${message}`}
            target="_blank"
            sx={{ mt: 1 }}
          >
            Validation link
          </Typography>
        </>
      )}
    </>
  );
};

const App = ({ kxUtil }) => {
  const [processStep, setProcessStep] = useState(0);
  const [keyList, setKeyList] = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);
  const [showTryAgainBtn, setShowTryAgainBtn] = useState(false);
  const [signResult, setSignResult] = useState(null);
  const [address, setAddress] = useState("");

  const onSignClick = (message, kxUtil) => {
    kxUtil.signData(message)
      .then((result) => {
        // Do something with the sign result. Usually you would send the request to BNS server.
        setSignResult(result);
      })
      .catch(() => {
        // Do something when sign data fail. Sometimes would happen when the token disconnect from the site.
        setShowTryAgainBtn(true);
      });
  };

  const startProcess = (kxUtil) => {
    setShowTryAgainBtn(false);
    setProcessStep(1);
    // Step1: Initial key. On the website, it's going to ask user to connect the key to the computer.
    kxUtil.initialKeyToken()
      .then(() => {
        // Step2: Verify Identity. On the website, it's going to ask user to use their fingerprint to login to the token.
        setProcessStep(2);
        kxUtil.loginToKeyTokenUsingFingerprint()
          .then(() => {
            // Step3: Read and ask user to choose the key to use on the website.
            kxUtil.getECCKeyList().then((keyList) => {
              setKeyList(keyList);
              setSelectedKey(keyList[0]);
              setProcessStep(3);
            });
          })
          .catch(() => {
            // Do something when the fingerprint login process is not successfully processed.
            setShowTryAgainBtn(true);
          });
      })
      .catch(() => {
        // Do something when the key token is not connect successfully. For example: show error message or try again button and ask the user to try again.
        setShowTryAgainBtn(true);
      });
  };

  const onKeySelect = (keyIndex) => {
    console.log("onKeySelect() key=", keyIndex);
    // keyIndex start from 1, but array start from 0
    setSelectedKey(keyList[keyIndex - 1]);
  };

  // Step4: When the user select key, sign the message
  const onKeyConfirm = (kxUtil) => {
    console.log("confirm click");
    kxUtil.setSelectKeyObj(selectedKey);
    setProcessStep(4);
  };

  return (
    <Box m={2}>
      <Button variant="contained" onClick={() => startProcess(kxUtil)}>
        Start
      </Button>
      {showTryAgainBtn && (
        // Normally we ask user to try again from the first step in case the token has lost the connection.
        <Button variant="outlined" onClick={() => startProcess(kxUtil)} sx={{ ml: 2 }}>
          Try Again
        </Button>
      )}
      <Box mt={1}>
        <ConnectionSteps
          activeStep={processStep}
          keyOption={{ list: keyList, select: selectedKey }}
          onKeySelect={onKeySelect}
          onConfirmClick={() => onKeyConfirm(kxUtil)}
          onSignClick={(message) => onSignClick(message, kxUtil)}
        />
      </Box>
      {processStep > 3 && (
        <Box mt={2}>
          <Typography variant="h5">
            Below are the method you could use after selecting the key.
          </Typography>
          <Box mt={2}>
            <SignYourData onSignClick={(message) => onSignClick(message, kxUtil)} signResult={signResult} kxUtil={kxUtil} />
          </Box>
          <Box mt={2}>
            <Button
              variant="contained"
              onClick={() => setAddress(kxUtil.obtainAddress())}
            >
              Obtain Address
            </Button>
            {address !== "" && (
              <Typography sx={{ mt: 1 }}>Address: {address}</Typography>
            )}
          </Box>
        </Box>
      )}
    </Box>

  );
};

export default App;