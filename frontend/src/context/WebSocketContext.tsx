import React, { createContext, useContext, useEffect, useState } from 'react';

interface LiveAlert {
  type: string;
  incident_number?: string;
  title?: string;
  severity?: string;
  confidence?: number;
  hostname?: string;
  timestamp: string;
}

interface WebSocketContextType {
  isConnected: boolean;
  alerts: LiveAlert[];
  unreadAlertCount: number;
  clearAlerts: () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [unreadAlertCount, setUnreadAlertCount] = useState(0);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/api/v1/ws/live`;

    let socket: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connect = () => {
      try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
          setIsConnected(true);
        };

        socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'NEW_INCIDENT' || data.type === 'NEW_EVENT') {
              setAlerts((prev) => [data, ...prev.slice(0, 49)]);
              if (data.type === 'NEW_INCIDENT') {
                setUnreadAlertCount((c) => c + 1);
              }
            }
          } catch {
            // Ignore keepalive or non-JSON
          }
        };

        socket.onclose = () => {
          setIsConnected(false);
          reconnectTimeout = setTimeout(connect, 4000);
        };

        socket.onerror = () => {
          socket?.close();
        };
      } catch {
        setIsConnected(false);
        reconnectTimeout = setTimeout(connect, 5000);
      }
    };

    connect();

    return () => {
      if (socket) socket.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  const clearAlerts = () => {
    setUnreadAlertCount(0);
  };

  return (
    <WebSocketContext.Provider value={{ isConnected, alerts, unreadAlertCount, clearAlerts }}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};
