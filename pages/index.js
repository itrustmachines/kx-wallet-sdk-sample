import App from '../components/App';

import dynamic from "next/dynamic";
const KxUtilWrapper = dynamic(() => import("../components/KxUtilWrapper"), {
  ssr: false,
});

const HomePage = () => {
  return (
    <div>
      <KxUtilWrapper>
        <App />
      </KxUtilWrapper>
    </div>
  );
};

export default HomePage;