import { WebSocketServer, WebSocket } from "ws";
declare const router: import("express-serve-static-core").Router;
/**
 * Combined WebSocket market stream route.
 * Connection URL: ws://.../v1/market-stream?pairs=USDC-XLM,BTC-USDC
 */
export declare const marketStreamPath = "/v1/market-stream";
export interface MarketStreamEvent {
    type: "price" | "volume" | "orderbook";
    pair: string;
    timestamp: number;
    data: unknown;
}
export interface MarketStreamClient {
    ws: WebSocket;
    pairs: Set<string>;
    format: "json" | "msgpack";
    isAlive: boolean;
    lastPing: number;
}
/**
 * Minimal MsgPack encoder for the market stream event shape.
 * Supports string, number, boolean, null, arrays and plain objects.
 */
export declare function encodeMsgPack(value: unknown): Uint8Array;
export declare function attachMarketStreamServer(server: any): WebSocketServer;
export declare function getMarketStreamMetrics(): {
    activeConnections: number;
    maxConnections: number;
};
export default router;
//# sourceMappingURL=priceUpdates.d.ts.map