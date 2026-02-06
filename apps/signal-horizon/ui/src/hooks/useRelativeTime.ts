import { useState, useEffect } from 'react';

export function useRelativeTime(timestamp: number | null) {
  const [text, setText] = useState('');

  useEffect(() => {
    if (!timestamp) return;

    const update = () => {
      const diff = Math.floor((Date.now() - timestamp) / 1000);
      if (diff < 5) setText('just now');
      else if (diff < 60) setText(`${diff}s ago`);
      else if (diff < 3600) setText(`${Math.floor(diff / 60)}m ago`);
      else setText(`${Math.floor(diff / 3600)}h ago`);
    };

    update();
    const interval = setInterval(update, 5000);
    return () => clearInterval(interval);
  }, [timestamp]);

  return text;
}
