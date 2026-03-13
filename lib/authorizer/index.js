"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = handler;
const crypto = __importStar(require("crypto"));
const https = __importStar(require("https"));
// Cache JWKS in Lambda memory (persists across warm invocations)
let cachedJwks = null;
let jwksCachedAt = 0;
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
function fetchJson(url) {
    return new Promise((resolve, reject) => {
        https
            .get(url, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                try {
                    resolve(JSON.parse(data));
                }
                catch (e) {
                    reject(e);
                }
            });
        })
            .on("error", reject);
    });
}
async function getJwks() {
    const now = Date.now();
    if (cachedJwks && now - jwksCachedAt < JWKS_CACHE_TTL_MS) {
        return cachedJwks;
    }
    const jwksUrl = `${process.env.OAUTH_SERVER_URL}/.well-known/jwks.json`;
    const jwks = (await fetchJson(jwksUrl));
    cachedJwks = jwks;
    jwksCachedAt = now;
    return jwks;
}
function base64urlDecode(str) {
    // Add padding
    const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function verifyRS256(token, jwk) {
    const parts = token.split(".");
    if (parts.length !== 3)
        return null;
    const [headerB64, payloadB64, signatureB64] = parts;
    // Build the public key from JWK
    const key = crypto.createPublicKey({
        key: { kty: jwk.kty, n: jwk.n, e: jwk.e },
        format: "jwk",
    });
    // Verify signature
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64urlDecode(signatureB64);
    const isValid = crypto.verify("sha256", Buffer.from(data), { key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
    if (!isValid)
        return null;
    return JSON.parse(base64urlDecode(payloadB64).toString());
}
async function handler(event) {
    const authHeader = event.headers?.authorization ?? event.headers?.Authorization;
    if (!authHeader?.startsWith("Bearer ")) {
        return { isAuthorized: true, context: { authenticated: "false" } };
    }
    const token = authHeader.slice(7);
    try {
        // Decode header to get kid
        const headerB64 = token.split(".")[0];
        const header = JSON.parse(base64urlDecode(headerB64).toString());
        if (header.alg !== "RS256") {
            return { isAuthorized: true, context: { authenticated: "false" } };
        }
        // Fetch JWKS
        const jwks = await getJwks();
        // Find matching key
        const jwk = header.kid
            ? jwks.keys.find((k) => k.kid === header.kid)
            : jwks.keys[0];
        if (!jwk) {
            return { isAuthorized: true, context: { authenticated: "false" } };
        }
        // Verify signature and decode
        const payload = verifyRS256(token, jwk);
        if (!payload) {
            return { isAuthorized: true, context: { authenticated: "false" } };
        }
        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (typeof payload.exp === "number" && payload.exp < now) {
            return { isAuthorized: true, context: { authenticated: "false" } };
        }
        // Check issuer
        if (payload.iss !== process.env.OAUTH_SERVER_URL) {
            return { isAuthorized: true, context: { authenticated: "false" } };
        }
        // Check org_id matches bound org
        if (payload.org_id !== process.env.BOUND_ORG_ID) {
            return { isAuthorized: true, context: { authenticated: "false" } };
        }
        return {
            isAuthorized: true,
            context: {
                userId: String(payload.sub ?? ""),
                orgId: String(payload.org_id ?? ""),
                orgRole: String(payload.org_role ?? ""),
            },
        };
    }
    catch {
        return { isAuthorized: true, context: { authenticated: "false" } };
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQWtHQSwwQkFvRUM7QUF0S0QsK0NBQWlDO0FBQ2pDLDZDQUErQjtBQTJCL0IsaUVBQWlFO0FBQ2pFLElBQUksVUFBVSxHQUFnQixJQUFJLENBQUM7QUFDbkMsSUFBSSxZQUFZLEdBQUcsQ0FBQyxDQUFDO0FBQ3JCLE1BQU0saUJBQWlCLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxJQUFJLENBQUMsQ0FBQyxTQUFTO0FBRW5ELFNBQVMsU0FBUyxDQUFDLEdBQVc7SUFDNUIsT0FBTyxJQUFJLE9BQU8sQ0FBQyxDQUFDLE9BQU8sRUFBRSxNQUFNLEVBQUUsRUFBRTtRQUNyQyxLQUFLO2FBQ0YsR0FBRyxDQUFDLEdBQUcsRUFBRSxDQUFDLEdBQUcsRUFBRSxFQUFFO1lBQ2hCLElBQUksSUFBSSxHQUFHLEVBQUUsQ0FBQztZQUNkLEdBQUcsQ0FBQyxFQUFFLENBQUMsTUFBTSxFQUFFLENBQUMsS0FBSyxFQUFFLEVBQUUsQ0FBQyxDQUFDLElBQUksSUFBSSxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQzNDLEdBQUcsQ0FBQyxFQUFFLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRTtnQkFDakIsSUFBSSxDQUFDO29CQUNILE9BQU8sQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUM7Z0JBQzVCLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztvQkFDWCxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7Z0JBQ1osQ0FBQztZQUNILENBQUMsQ0FBQyxDQUFDO1FBQ0wsQ0FBQyxDQUFDO2FBQ0QsRUFBRSxDQUFDLE9BQU8sRUFBRSxNQUFNLENBQUMsQ0FBQztJQUN6QixDQUFDLENBQUMsQ0FBQztBQUNMLENBQUM7QUFFRCxLQUFLLFVBQVUsT0FBTztJQUNw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QUM7SUFDckUsQ0FBQztBQUNILENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBjcnlwdG8gZnJvbSBcImNyeXB0b1wiO1xuaW1wb3J0ICogYXMgaHR0cHMgZnJvbSBcImh0dHBzXCI7XG5cbmludGVyZmFjZSBBdXRob3JpemVyRXZlbnQge1xuICBoZWFkZXJzPzogUmVjb3JkPHN0cmluZywgc3RyaW5nPjtcbiAgcmVxdWVzdENvbnRleHQ/OiB7XG4gICAgaHR0cD86IHsgbWV0aG9kOiBzdHJpbmc7IHBhdGg6IHN0cmluZyB9O1xuICB9O1xufVxuXG5pbnRlcmZhY2UgQXV0aG9yaXplclJlc3VsdCB7XG4gIGlzQXV0aG9yaXplZDogYm9vbGVhbjtcbiAgY29udGV4dD86IFJlY29yZDxzdHJpbmcsIHN0cmluZz47XG59XG5cbmludGVyZmFjZSBKV0sge1xuICBrdHk6IHN0cmluZztcbiAgbjogc3RyaW5nO1xuICBlOiBzdHJpbmc7XG4gIGFsZz86IHN0cmluZztcbiAga2lkPzogc3RyaW5nO1xuICB1c2U/OiBzdHJpbmc7XG59XG5cbmludGVyZmFjZSBKV0tTIHtcbiAga2V5czogSldLW107XG59XG5cbi8vIENhY2hlIEpXS1MgaW4gTGFtYmRhIG1lbW9yeSAocGVyc2lzdHMgYWNyb3NzIHdhcm0gaW52b2NhdGlvbnMpXG5sZXQgY2FjaGVkSndrczogSldLUyB8IG51bGwgPSBudWxsO1xubGV0IGp3a3NDYWNoZWRBdCA9IDA7XG5jb25zdCBKV0tTX0NBQ0hFX1RUTF9NUyA9IDYwICogNjAgKiAxMDAwOyAvLyAxIGhvdXJcblxuZnVuY3Rpb24gZmV0Y2hKc29uKHVybDogc3RyaW5nKTogUHJvbWlzZTx1bmtub3duPiB7XG4gIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgaHR0cHNcbiAgICAgIC5nZXQodXJsLCAocmVzKSA9PiB7XG4gICAgICAgIGxldCBkYXRhID0gXCJcIjtcbiAgICAgICAgcmVzLm9uKFwiZGF0YVwiLCAoY2h1bmspID0+IChkYXRhICs9IGNodW5rKSk7XG4gICAgICAgIHJlcy5vbihcImVuZFwiLCAoKSA9PiB7XG4gICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJlc29sdmUoSlNPTi5wYXJzZShkYXRhKSk7XG4gICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgcmVqZWN0KGUpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9KVxuICAgICAgLm9uKFwiZXJyb3JcIiwgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGdldEp3a3MoKTogUHJvbWlzZTxKV0tTPiB7XG4gIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gIGlmIChjYWNoZWRKd2tzICYmIG5vdyAtIGp3a3NDYWNoZWRBdCA8IEpXS1NfQ0FDSEVfVFRMX01TKSB7XG4gICAgcmV0dXJuIGNhY2hlZEp3a3M7XG4gIH1cblxuICBjb25zdCBqd2tzVXJsID0gYCR7cHJvY2Vzcy5lbnYuT0FVVEhfU0VSVkVSX1VSTH0vLndlbGwta25vd24vandrcy5qc29uYDtcbiAgY29uc3QgandrcyA9IChhd2FpdCBmZXRjaEpzb24oandrc1VybCkpIGFzIEpXS1M7XG4gIGNhY2hlZEp3a3MgPSBqd2tzO1xuICBqd2tzQ2FjaGVkQXQgPSBub3c7XG4gIHJldHVybiBqd2tzO1xufVxuXG5mdW5jdGlvbiBiYXNlNjR1cmxEZWNvZGUoc3RyOiBzdHJpbmcpOiBCdWZmZXIge1xuICAvLyBBZGQgcGFkZGluZ1xuICBjb25zdCBwYWRkZWQgPSBzdHIgKyBcIj1cIi5yZXBlYXQoKDQgLSAoc3RyLmxlbmd0aCAlIDQpKSAlIDQpO1xuICByZXR1cm4gQnVmZmVyLmZyb20ocGFkZGVkLnJlcGxhY2UoLy0vZywgXCIrXCIpLnJlcGxhY2UoL18vZywgXCIvXCIpLCBcImJhc2U2NFwiKTtcbn1cblxuZnVuY3Rpb24gdmVyaWZ5UlMyNTYodG9rZW46IHN0cmluZywgandrOiBKV0spOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiB8IG51bGwge1xuICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KFwiLlwiKTtcbiAgaWYgKHBhcnRzLmxlbmd0aCAhPT0gMykgcmV0dXJuIG51bGw7XG5cbiAgY29uc3QgW2hlYWRlckI2NCwgcGF5bG9hZEI2NCwgc2lnbmF0dXJlQjY0XSA9IHBhcnRzO1xuXG4gIC8vIEJ1aWxkIHRoZSBwdWJsaWMga2V5IGZyb20gSldLXG4gIGNvbnN0IGtleSA9IGNyeXB0by5jcmVhdGVQdWJsaWNLZXkoe1xuICAgIGtleTogeyBrdHk6IGp3ay5rdHksIG46IGp3ay5uLCBlOiBqd2suZSB9LFxuICAgIGZvcm1hdDogXCJqd2tcIixcbiAgfSk7XG5cbiAgLy8gVmVyaWZ5IHNpZ25hdHVyZVxuICBjb25zdCBkYXRhID0gYCR7aGVhZGVyQjY0fS4ke3BheWxvYWRCNjR9YDtcbiAgY29uc3Qgc2lnbmF0dXJlID0gYmFzZTY0dXJsRGVjb2RlKHNpZ25hdHVyZUI2NCk7XG5cbiAgY29uc3QgaXNWYWxpZCA9IGNyeXB0by52ZXJpZnkoXG4gICAgXCJzaGEyNTZcIixcbiAgICBCdWZmZXIuZnJvbShkYXRhKSxcbiAgICB7IGtleSwgcGFkZGluZzogY3J5cHRvLmNvbnN0YW50cy5SU0FfUEtDUzFfUEFERElORyB9LFxuICAgIHNpZ25hdHVyZVxuICApO1xuXG4gIGlmICghaXNWYWxpZCkgcmV0dXJuIG51bGw7XG5cbiAgcmV0dXJuIEpTT04ucGFyc2UoYmFzZTY0dXJsRGVjb2RlKHBheWxvYWRCNjQpLnRvU3RyaW5nKCkpO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaGFuZGxlcihcbiAgZXZlbnQ6IEF1dGhvcml6ZXJFdmVudFxuKTogUHJvbWlzZTxBdXRob3JpemVyUmVzdWx0PiB7XG4gIGNvbnN0IGF1dGhIZWFkZXIgPVxuICAgIGV2ZW50LmhlYWRlcnM/LmF1dGhvcml6YXRpb24gPz8gZXZlbnQuaGVhZGVycz8uQXV0aG9yaXphdGlvbjtcbiAgaWYgKCFhdXRoSGVhZGVyPy5zdGFydHNXaXRoKFwiQmVhcmVyIFwiKSkge1xuICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogdHJ1ZSwgY29udGV4dDogeyBhdXRoZW50aWNhdGVkOiBcImZhbHNlXCIgfSB9O1xuICB9XG5cbiAgY29uc3QgdG9rZW4gPSBhdXRoSGVhZGVyLnNsaWNlKDcpO1xuXG4gIHRyeSB7XG4gICAgLy8gRGVjb2RlIGhlYWRlciB0byBnZXQga2lkXG4gICAgY29uc3QgaGVhZGVyQjY0ID0gdG9rZW4uc3BsaXQoXCIuXCIpWzBdO1xuICAgIGNvbnN0IGhlYWRlciA9IEpTT04ucGFyc2UoYmFzZTY0dXJsRGVjb2RlKGhlYWRlckI2NCkudG9TdHJpbmcoKSkgYXMge1xuICAgICAgYWxnOiBzdHJpbmc7XG4gICAgICBraWQ/OiBzdHJpbmc7XG4gICAgfTtcblxuICAgIGlmIChoZWFkZXIuYWxnICE9PSBcIlJTMjU2XCIpIHtcbiAgICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogdHJ1ZSwgY29udGV4dDogeyBhdXRoZW50aWNhdGVkOiBcImZhbHNlXCIgfSB9O1xuICAgIH1cblxuICAgIC8vIEZldGNoIEpXS1NcbiAgICBjb25zdCBqd2tzID0gYXdhaXQgZ2V0SndrcygpO1xuXG4gICAgLy8gRmluZCBtYXRjaGluZyBrZXlcbiAgICBjb25zdCBqd2sgPSBoZWFkZXIua2lkXG4gICAgICA/IGp3a3Mua2V5cy5maW5kKChrKSA9PiBrLmtpZCA9PT0gaGVhZGVyLmtpZClcbiAgICAgIDogandrcy5rZXlzWzBdO1xuXG4gICAgaWYgKCFqd2spIHtcbiAgICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogdHJ1ZSwgY29udGV4dDogeyBhdXRoZW50aWNhdGVkOiBcImZhbHNlXCIgfSB9O1xuICAgIH1cblxuICAgIC8vIFZlcmlmeSBzaWduYXR1cmUgYW5kIGRlY29kZVxuICAgIGNvbnN0IHBheWxvYWQgPSB2ZXJpZnlSUzI1Nih0b2tlbiwgandrKTtcbiAgICBpZiAoIXBheWxvYWQpIHtcbiAgICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogdHJ1ZSwgY29udGV4dDogeyBhdXRoZW50aWNhdGVkOiBcImZhbHNlXCIgfSB9O1xuICAgIH1cblxuICAgIC8vIENoZWNrIGV4cGlyYXRpb25cbiAgICBjb25zdCBub3cgPSBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKTtcbiAgICBpZiAodHlwZW9mIHBheWxvYWQuZXhwID09PSBcIm51bWJlclwiICYmIHBheWxvYWQuZXhwIDwgbm93KSB7XG4gICAgICByZXR1cm4geyBpc0F1dGhvcml6ZWQ6IHRydWUsIGNvbnRleHQ6IHsgYXV0aGVudGljYXRlZDogXCJmYWxzZVwiIH0gfTtcbiAgICB9XG5cbiAgICAvLyBDaGVjayBpc3N1ZXJcbiAgICBpZiAocGF5bG9hZC5pc3MgIT09IHByb2Nlc3MuZW52Lk9BVVRIX1NFUlZFUl9VUkwpIHtcbiAgICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogdHJ1ZSwgY29udGV4dDogeyBhdXRoZW50aWNhdGVkOiBcImZhbHNlXCIgfSB9O1xuICAgIH1cblxuICAgIC8vIENoZWNrIG9yZ19pZCBtYXRjaGVzIGJvdW5kIG9yZ1xuICAgIGlmIChwYXlsb2FkLm9yZ19pZCAhPT0gcHJvY2Vzcy5lbnYuQk9VTkRfT1JHX0lEKSB7XG4gICAgICByZXR1cm4geyBpc0F1dGhvcml6ZWQ6IHRydWUsIGNvbnRleHQ6IHsgYXV0aGVudGljYXRlZDogXCJmYWxzZVwiIH0gfTtcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgaXNBdXRob3JpemVkOiB0cnVlLFxuICAgICAgY29udGV4dDoge1xuICAgICAgICB1c2VySWQ6IFN0cmluZyhwYXlsb2FkLnN1YiA/PyBcIlwiKSxcbiAgICAgICAgb3JnSWQ6IFN0cmluZyhwYXlsb2FkLm9yZ19pZCA/PyBcIlwiKSxcbiAgICAgICAgb3JnUm9sZTogU3RyaW5nKHBheWxvYWQub3JnX3JvbGUgPz8gXCJcIiksXG4gICAgICB9LFxuICAgIH07XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogdHJ1ZSwgY29udGV4dDogeyBhdXRoZW50aWNhdGVkOiBcImZhbHNlXCIgfSB9O1xuICB9XG59XG4iXX0=