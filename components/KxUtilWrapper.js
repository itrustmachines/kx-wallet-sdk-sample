import React, { useEffect, useState } from "react";

const KxUtilWrapper = ({ children }) => {
  const [kxUtil, setKxUtil] = useState(null);

  useEffect(() => {
    import("../utils/kxUtil").then((kxUtilModule) => {
      setKxUtil(kxUtilModule);
    });
  }, []);

  if (!kxUtil) {
    return <div>Loading...</div>;
  }

  return React.cloneElement(children, { kxUtil });
};

export default KxUtilWrapper;
