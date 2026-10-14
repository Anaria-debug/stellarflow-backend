import { Server } from "socket.io";
interface MarketEvent {
    type: "price" | "volume" | "orderbook";
    pair: string;
    data: any;
    timestamp: number;
}
/**
 * Broadcasts an event to all connected clients and queues it for those in grace period.
 */
export declare function broadcastToSessions(event: string, data: any): void;
/**
 * Publishes a market event to all subscribed sockets for the given pair.
 * Multiplexes price, volume, and order book updates into a single stream.
 */
export declare function publishMarketEvent(event: MarketEvent): void;
/**
 * Returns memory overhead estimate for active client connections.
 * Used to validate support for 10,000 active sockets.
 */
export declare function getConnectionMemoryStats(): {
    activeSockets: any;
    activeSessions: number;
    activeSubscriptions: number;
    heapUsed: number;
    rss: number;
    estimatedBytesPerSocket: any;
    0: any;
    supports10k: boolean;
};
export declare function initSocket(server: import("http").Server): Server;
export declare function getIO(): Server;
export {};
//# sourceMappingURL=socket.d.ts.map