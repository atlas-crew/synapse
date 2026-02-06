import { useEffect } from 'react';

export function useDocumentTitle(title: string) {
  useEffect(() => {
    const prev = document.title;
    document.title = title ? `${title} | Signal Horizon` : 'Signal Horizon';
    return () => {
      document.title = prev;
    };
  }, [title]);
}
