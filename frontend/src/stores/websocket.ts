interface WsMessage {
  task_id: string;
  event: string;
  payload: Record<string, unknown>;
}

type Listener = (msg: WsMessage) => void;

class WebSocketManager {
  private ws: WebSocket | null = null;
  private listeners: Set<Listener> = new Set();
  private currentTaskId: string | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  connect(taskId: string) {
    this.disconnect();
    this.currentTaskId = taskId;

    const wsBase = import.meta.env.VITE_WS_BASE_URL || 'ws://127.0.0.1:8001/api/v1/ws';
    const url = `${wsBase}/tasks/${taskId}`;
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      console.log('[WS] connected to task:', taskId);
    };

    this.ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as WsMessage;
        this.listeners.forEach((fn) => fn(msg));
      } catch {
        // ignore non-JSON
      }
    };

    this.ws.onclose = () => {
      console.log('[WS] closed');
      this.ws = null;
    };

    this.ws.onerror = () => {
      console.error('[WS] error');
    };
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.currentTaskId = null;
  }

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  sendPing() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send('ping');
    }
  }
}

export const wsManager = new WebSocketManager();
