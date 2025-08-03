import { useEffect, useState } from "react";
import "./StatusBar.css";

function StatusBar({ status }) {
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    setIsVisible(true);
  }, [status.message]);

  useEffect(() => {
    if (!isVisible) return;

    const timer = setTimeout(() => {
      setIsVisible(false);
    }, 2000);

    return () => clearTimeout(timer);
  }, [isVisible]);

  if (!isVisible) return null;

  return <div className={`status ${status.type}`}>{status.message}</div>;
}

export default StatusBar;
