First of all, as I am not familiar with Next.js technology, please let me know if there is any issue.

I attempted to rewrite the original React example into a Next.js version. I moved the `src/lib` and `src/function` directories to a new `util` directory at the root level. Then, I moved `src/index.js` and `src/index.css` to the `pages` directory. I also made the necessary modifications to the `package.json` file. At this stage, I was able to reproduce the "this undefined" error mentioned in the article.

---

I created a `KxUtilWrapper` component to provide dynamic loading. When the module is successfully loaded, it is added as a prop to this component. If the module is not yet loaded, the component displays "Loading."

```react
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
```

---

I modified the relevant blocks of code in `App.js` that import the following:

```react
import {

  getECCKeyList,

  initialKeyToken,

  loginToKeyTokenUsingFingerprint,

  obtainAddress,

  setSelectKeyObj,

  signData,

} from "./function/kxUtil";
```

For example, because `signData` uses `kxUtil`, I made the following modification to `onSignClick`:

```
// before
const onSignClick = (message) => {
    signData(message)
      /// Skip
  };
```

```
// after
const onSignClick = (message, kxUtil) => {
    kxUtil.signData(message)
      /// Skip
  };
```

I also passed `kxUtil` to `App`:

```
// before
function App() {
```

```
// after
const App = ({ kxUtil }) => {
```

---

Finally, I used the `next/dynamic` package to dynamically load the previously written Wrapper:

```
import dynamic from "next/dynamic";
const KxUtilWrapper = dynamic(() => import("../components/KxUtilWrapper"), {
  ssr: false,
});
```

I wrapped the modules that will use `kxUtil` with `KxUtilWrapper`:

```
const HomePage = () => {
  return (
    <div>
      <KxUtilWrapper>
        <App />
      </KxUtilWrapper>
    </div>
  );
};
```

---

I referred to the Next.js documentation to write a corresponding `Dockerfile, Dockerfile-build` and tested the `npm run dev` and `build` results. I also provided a `docker-compose` method for use. Please feel free to contact us if you have any issues, and we will do our best to assist you.