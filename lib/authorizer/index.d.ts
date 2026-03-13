interface AuthorizerEvent {
    headers?: Record<string, string>;
    requestContext?: {
        http?: {
            method: string;
            path: string;
        };
    };
}
interface AuthorizerResult {
    isAuthorized: boolean;
    context?: Record<string, string>;
}
export declare function handler(event: AuthorizerEvent): Promise<AuthorizerResult>;
export {};
