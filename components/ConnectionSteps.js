import React from "react";
import PropTypes from "prop-types";
import { Button, MenuItem, Stack, TextField, Typography } from "@mui/material";
import { Box } from "@mui/system";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import PlayArrowOutlinedIcon from "@mui/icons-material/PlayArrowOutlined";
import language from "./language";

const KeyOption = ({ keyList, select, onSelect }) => {
  return (
    <Box display="flex" flexDirection="row" alignItems="center">
      <Typography variant="body1" color="textPrimary">
        Key List:
      </Typography>
      <TextField
        id="keys-dropdown"
        name="keys"
        value={select?.keyIndex || keyList[0].keyIndex}
        select
        variant="outlined"
        size="small"
        color="secondary"
        onChange={(event) => {
          onSelect(event.target.value);
        }}
        sx={{ ml: 1 }}
      >
        {keyList.map((key) => (
          <MenuItem key={key.keyIndex} value={key.keyIndex}>
            {key.label}
          </MenuItem>
        ))}
      </TextField>
    </Box>
  );
};

KeyOption.propTypes = {
  keyList: PropTypes.array.isRequired,
  select: PropTypes.object,
  onSelect: PropTypes.func.isRequired,
};

const Step = ({
  number,
  isDone,
  title,
  description,
  keyOption,
  onKeySelect,
  onConfirmClick,
}) => {
  const mainColor = isDone ? "primary" : "error";
  return (
    <>
      <Box display="flex" flexDirection="row">
        {isDone ? (
          <CheckCircleRoundedIcon
            color="primary"
            sx={{ width: "28px", height: "24px", mt: "1px" }}
          />
        ) : (
          <PlayArrowOutlinedIcon
            sx={{ width: "28px", height: "28px" }}
            color="error"
          />
        )}
        <Box>
          <Box display="flex" alignItems="center">
            <Typography
              variant="h6"
              color={mainColor}
            >{`Step.${number} ${title}`}</Typography>
            {number === 3 && isDone && (
              <Box
                sx={{
                  ml: 1,
                  border: 1,
                  borderColor: "secondary.main",
                  borderRadius: "5px",
                }}
              >
                <Typography
                  variant="body1"
                  color="secondary"
                  lineHeight="normal"
                  letterSpacing={0.5}
                  sx={{ px: 1, py: 0.5 }}
                >
                  {keyOption?.select.label}
                </Typography>
              </Box>
            )}
          </Box>
          {!isDone && (
            <Typography variant="body1" color="textPrimary">
              {description}
            </Typography>
          )}
          {number === 3 &&
            !isDone &&
            keyOption &&
            keyOption.list?.length > 0 && (
              <Box
                display="flex"
                flexDirection="row"
                alignItems="center"
                mt={1}
              >
                <KeyOption
                  keyList={keyOption.list}
                  select={keyOption.select}
                  onSelect={onKeySelect}
                />
                <Button
                  variant="contained"
                  color="primary"
                  sx={{ ml: 1 }}
                  onClick={onConfirmClick}
                >
                  Confirm
                </Button>
              </Box>
            )}
        </Box>
      </Box>
    </>
  );
};

Step.propTypes = {
  number: PropTypes.number.isRequired,
  isDone: PropTypes.bool.isRequired,
  title: PropTypes.string.isRequired,
  description: PropTypes.any,
  keyOption: PropTypes.object,
  onKeySelect: PropTypes.func,
  onConfirmClick: PropTypes.func,
};

const ConnectionSteps = ({
  activeStep,
  keyOption,
  onKeySelect,
  onConfirmClick,
  onSignClick,
}) => {
  const contents = [
    {
      number: 1,
      titleKey: "connectTokenToWebsiteTitle",
      descriptionKey: "kxTokenStep1Text",
    },
    {
      number: 2,
      titleKey: "verifyIdentityTitle",
      descriptionKey: "kxTokenStep2Text",
    },
    {
      number: 3,
      titleKey: "selectYourPrivateKeyTitle",
      descriptionKey: "kxTokenStep3Text",
    },
    // {
    //   number: 4,
    //   titleKey: "procedureProcessingTitle",
    //   descriptionKey: "kxTokenStep4Text",
    // },
  ];
  return (
    <React.Fragment>
      <Stack spacing={1}>
        {contents.map((content, index) => {
          return content.number <= activeStep ? (
            <Step
              key={`step-${index}`}
              number={content.number}
              isDone={content.number < activeStep}
              title={language[content.titleKey]}
              description={language[content.descriptionKey]}
              keyOption={keyOption}
              onKeySelect={onKeySelect}
              onConfirmClick={onConfirmClick}
              onSignClick={onSignClick}
            />
          ) : null;
        })}
      </Stack>
    </React.Fragment>
  );
};

ConnectionSteps.propTypes = {
  activeStep: PropTypes.number.isRequired,
  keyOption: PropTypes.object,
  onKeySelect: PropTypes.func,
  onConfirmClick: PropTypes.func,
};

export default ConnectionSteps;
