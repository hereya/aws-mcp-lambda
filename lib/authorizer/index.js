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
        return { isAuthorized: false };
    }
    const token = authHeader.slice(7);
    try {
        // Decode header to get kid
        const headerB64 = token.split(".")[0];
        const header = JSON.parse(base64urlDecode(headerB64).toString());
        if (header.alg !== "RS256") {
            return { isAuthorized: false };
        }
        // Fetch JWKS
        const jwks = await getJwks();
        // Find matching key
        const jwk = header.kid
            ? jwks.keys.find((k) => k.kid === header.kid)
            : jwks.keys[0];
        if (!jwk) {
            return { isAuthorized: false };
        }
        // Verify signature and decode
        const payload = verifyRS256(token, jwk);
        if (!payload) {
            return { isAuthorized: false };
        }
        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (typeof payload.exp === "number" && payload.exp < now) {
            return { isAuthorized: false };
        }
        // Check issuer
        if (payload.iss !== process.env.OAUTH_SERVER_URL) {
            return { isAuthorized: false };
        }
        // Check org_id matches bound org
        if (payload.org_id !== process.env.BOUND_ORG_ID) {
            return { isAuthorized: false };
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
        return { isAuthorized: false };
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQWtHQSwwQkFvRUM7QUF0S0QsK0NBQWlDO0FBQ2pDLDZDQUErQjtBQTJCL0IsaUVBQWlFO0FBQ2pFLElBQUksVUFBVSxHQUFnQixJQUFJLENBQUM7QUFDbkMsSUFBSSxZQUFZLEdBQUcsQ0FBQyxDQUFDO0FBQ3JCLE1BQU0saUJBQWlCLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxJQUFJLENBQUMsQ0FBQyxTQUFTO0FBRW5ELFNBQVMsU0FBUyxDQUFDLEdBQVc7SUFDNUIsT0FBTyxJQUFJLE9BQU8sQ0FBQyxDQUFDLE9BQU8sRUFBRSxNQUFNLEVBQUUsRUFBRTtRQUNyQyxLQUFLO2FBQ0YsR0FBRyxDQUFDLEdBQUcsRUFBRSxDQUFDLEdBQUcsRUFBRSxFQUFFO1lBQ2hCLElBQUksSUFBSSxHQUFHLEVBQUUsQ0FBQztZQUNkLEdBQUcsQ0FBQyxFQUFFLENBQUMsTUFBTSxFQUFFLENBQUMsS0FBSyxFQUFFLEVBQUUsQ0FBQyxDQUFDLElBQUksSUFBSSxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQzNDLEdBQUcsQ0FBQyxFQUFFLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRTtnQkFDakIsSUFBSSxDQUFDO29CQUNILE9BQU8sQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUM7Z0JBQzVCLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztvQkFDWCxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7Z0JBQ1osQ0FBQztZQUNILENBQUMsQ0FBQyxDQUFDO1FBQ0wsQ0FBQyxDQUFDO2FBQ0QsRUFBRSxDQUFDLE9BQU8sRUFBRSxNQUFNLENBQUMsQ0FBQztJQUN6QixDQUFDLENBQUMsQ0FBQztBQUNMLENBQUM7QUFFRCxLQUFLLFVBQVUsT0FBTztJQUNw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LEtBQUssRUFBRSxDQUFDO1FBQ2pDLENBQUM7UUFFRCxlQUFlO1FBQ2YsSUFBSSxPQUFPLENBQUMsR0FBRyxLQUFLLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCLEVBQUUsQ0FBQztZQUNqRCxPQUFPLEVBQUUsWUFBWSxFQUFFLEtBQUssRUFBRSxDQUFDO1FBQ2pDLENBQUM7UUFFRCxpQ0FBaUM7UUFDakMsSUFBSSxPQUFPLENBQUMsTUFBTSxLQUFLLE9BQU8sQ0FBQyxHQUFHLENBQUMsWUFBWSxFQUFFLENBQUM7WUFDaEQsT0FBTyxFQUFFLFlBQVksRUFBRSxLQUFLLEVBQUUsQ0FBQztRQUNqQyxDQUFDO1FBRUQsT0FBTztZQUNMLFlBQVksRUFBRSxJQUFJO1lBQ2xCLE9BQU8sRUFBRTtnQkFDUCxNQUFNLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxHQUFHLElBQUksRUFBRSxDQUFDO2dCQUNqQyxLQUFLLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxNQUFNLElBQUksRUFBRSxDQUFDO2dCQUNuQyxPQUFPLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxRQUFRLElBQUksRUFBRSxDQUFDO2FBQ3hDO1NBQ0YsQ0FBQztJQUNKLENBQUM7SUFBQyxNQUFNLENBQUM7UUFDUCxPQUFPLEVBQUUsWUFBWSxFQUFFLEtBQUssRUFBRSxDQUFDO0lBQ2pDLENBQUM7QUFDSCxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgY3J5cHRvIGZyb20gXCJjcnlwdG9cIjtcbmltcG9ydCAqIGFzIGh0dHBzIGZyb20gXCJodHRwc1wiO1xuXG5pbnRlcmZhY2UgQXV0aG9yaXplckV2ZW50IHtcbiAgaGVhZGVycz86IFJlY29yZDxzdHJpbmcsIHN0cmluZz47XG4gIHJlcXVlc3RDb250ZXh0Pzoge1xuICAgIGh0dHA/OiB7IG1ldGhvZDogc3RyaW5nOyBwYXRoOiBzdHJpbmcgfTtcbiAgfTtcbn1cblxuaW50ZXJmYWNlIEF1dGhvcml6ZXJSZXN1bHQge1xuICBpc0F1dGhvcml6ZWQ6IGJvb2xlYW47XG4gIGNvbnRleHQ/OiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+O1xufVxuXG5pbnRlcmZhY2UgSldLIHtcbiAga3R5OiBzdHJpbmc7XG4gIG46IHN0cmluZztcbiAgZTogc3RyaW5nO1xuICBhbGc/OiBzdHJpbmc7XG4gIGtpZD86IHN0cmluZztcbiAgdXNlPzogc3RyaW5nO1xufVxuXG5pbnRlcmZhY2UgSldLUyB7XG4gIGtleXM6IEpXS1tdO1xufVxuXG4vLyBDYWNoZSBKV0tTIGluIExhbWJkYSBtZW1vcnkgKHBlcnNpc3RzIGFjcm9zcyB3YXJtIGludm9jYXRpb25zKVxubGV0IGNhY2hlZEp3a3M6IEpXS1MgfCBudWxsID0gbnVsbDtcbmxldCBqd2tzQ2FjaGVkQXQgPSAwO1xuY29uc3QgSldLU19DQUNIRV9UVExfTVMgPSA2MCAqIDYwICogMTAwMDsgLy8gMSBob3VyXG5cbmZ1bmN0aW9uIGZldGNoSnNvbih1cmw6IHN0cmluZyk6IFByb21pc2U8dW5rbm93bj4ge1xuICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgIGh0dHBzXG4gICAgICAuZ2V0KHVybCwgKHJlcykgPT4ge1xuICAgICAgICBsZXQgZGF0YSA9IFwiXCI7XG4gICAgICAgIHJlcy5vbihcImRhdGFcIiwgKGNodW5rKSA9PiAoZGF0YSArPSBjaHVuaykpO1xuICAgICAgICByZXMub24oXCJlbmRcIiwgKCkgPT4ge1xuICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXNvbHZlKEpTT04ucGFyc2UoZGF0YSkpO1xuICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIHJlamVjdChlKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSlcbiAgICAgIC5vbihcImVycm9yXCIsIHJlamVjdCk7XG4gIH0pO1xufVxuXG5hc3luYyBmdW5jdGlvbiBnZXRKd2tzKCk6IFByb21pc2U8SldLUz4ge1xuICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICBpZiAoY2FjaGVkSndrcyAmJiBub3cgLSBqd2tzQ2FjaGVkQXQgPCBKV0tTX0NBQ0hFX1RUTF9NUykge1xuICAgIHJldHVybiBjYWNoZWRKd2tzO1xuICB9XG5cbiAgY29uc3Qgandrc1VybCA9IGAke3Byb2Nlc3MuZW52Lk9BVVRIX1NFUlZFUl9VUkx9Ly53ZWxsLWtub3duL2p3a3MuanNvbmA7XG4gIGNvbnN0IGp3a3MgPSAoYXdhaXQgZmV0Y2hKc29uKGp3a3NVcmwpKSBhcyBKV0tTO1xuICBjYWNoZWRKd2tzID0gandrcztcbiAgandrc0NhY2hlZEF0ID0gbm93O1xuICByZXR1cm4gandrcztcbn1cblxuZnVuY3Rpb24gYmFzZTY0dXJsRGVjb2RlKHN0cjogc3RyaW5nKTogQnVmZmVyIHtcbiAgLy8gQWRkIHBhZGRpbmdcbiAgY29uc3QgcGFkZGVkID0gc3RyICsgXCI9XCIucmVwZWF0KCg0IC0gKHN0ci5sZW5ndGggJSA0KSkgJSA0KTtcbiAgcmV0dXJuIEJ1ZmZlci5mcm9tKHBhZGRlZC5yZXBsYWNlKC8tL2csIFwiK1wiKS5yZXBsYWNlKC9fL2csIFwiL1wiKSwgXCJiYXNlNjRcIik7XG59XG5cbmZ1bmN0aW9uIHZlcmlmeVJTMjU2KHRva2VuOiBzdHJpbmcsIGp3azogSldLKTogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gfCBudWxsIHtcbiAgY29uc3QgcGFydHMgPSB0b2tlbi5zcGxpdChcIi5cIik7XG4gIGlmIChwYXJ0cy5sZW5ndGggIT09IDMpIHJldHVybiBudWxsO1xuXG4gIGNvbnN0IFtoZWFkZXJCNjQsIHBheWxvYWRCNjQsIHNpZ25hdHVyZUI2NF0gPSBwYXJ0cztcblxuICAvLyBCdWlsZCB0aGUgcHVibGljIGtleSBmcm9tIEpXS1xuICBjb25zdCBrZXkgPSBjcnlwdG8uY3JlYXRlUHVibGljS2V5KHtcbiAgICBrZXk6IHsga3R5OiBqd2sua3R5LCBuOiBqd2subiwgZTogandrLmUgfSxcbiAgICBmb3JtYXQ6IFwiandrXCIsXG4gIH0pO1xuXG4gIC8vIFZlcmlmeSBzaWduYXR1cmVcbiAgY29uc3QgZGF0YSA9IGAke2hlYWRlckI2NH0uJHtwYXlsb2FkQjY0fWA7XG4gIGNvbnN0IHNpZ25hdHVyZSA9IGJhc2U2NHVybERlY29kZShzaWduYXR1cmVCNjQpO1xuXG4gIGNvbnN0IGlzVmFsaWQgPSBjcnlwdG8udmVyaWZ5KFxuICAgIFwic2hhMjU2XCIsXG4gICAgQnVmZmVyLmZyb20oZGF0YSksXG4gICAgeyBrZXksIHBhZGRpbmc6IGNyeXB0by5jb25zdGFudHMuUlNBX1BLQ1MxX1BBRERJTkcgfSxcbiAgICBzaWduYXR1cmVcbiAgKTtcblxuICBpZiAoIWlzVmFsaWQpIHJldHVybiBudWxsO1xuXG4gIHJldHVybiBKU09OLnBhcnNlKGJhc2U2NHVybERlY29kZShwYXlsb2FkQjY0KS50b1N0cmluZygpKTtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGhhbmRsZXIoXG4gIGV2ZW50OiBBdXRob3JpemVyRXZlbnRcbik6IFByb21pc2U8QXV0aG9yaXplclJlc3VsdD4ge1xuICBjb25zdCBhdXRoSGVhZGVyID1cbiAgICBldmVudC5oZWFkZXJzPy5hdXRob3JpemF0aW9uID8/IGV2ZW50LmhlYWRlcnM/LkF1dGhvcml6YXRpb247XG4gIGlmICghYXV0aEhlYWRlcj8uc3RhcnRzV2l0aChcIkJlYXJlciBcIikpIHtcbiAgICByZXR1cm4geyBpc0F1dGhvcml6ZWQ6IGZhbHNlIH07XG4gIH1cblxuICBjb25zdCB0b2tlbiA9IGF1dGhIZWFkZXIuc2xpY2UoNyk7XG5cbiAgdHJ5IHtcbiAgICAvLyBEZWNvZGUgaGVhZGVyIHRvIGdldCBraWRcbiAgICBjb25zdCBoZWFkZXJCNjQgPSB0b2tlbi5zcGxpdChcIi5cIilbMF07XG4gICAgY29uc3QgaGVhZGVyID0gSlNPTi5wYXJzZShiYXNlNjR1cmxEZWNvZGUoaGVhZGVyQjY0KS50b1N0cmluZygpKSBhcyB7XG4gICAgICBhbGc6IHN0cmluZztcbiAgICAgIGtpZD86IHN0cmluZztcbiAgICB9O1xuXG4gICAgaWYgKGhlYWRlci5hbGcgIT09IFwiUlMyNTZcIikge1xuICAgICAgcmV0dXJuIHsgaXNBdXRob3JpemVkOiBmYWxzZSB9O1xuICAgIH1cblxuICAgIC8vIEZldGNoIEpXS1NcbiAgICBjb25zdCBqd2tzID0gYXdhaXQgZ2V0SndrcygpO1xuXG4gICAgLy8gRmluZCBtYXRjaGluZyBrZXlcbiAgICBjb25zdCBqd2sgPSBoZWFkZXIua2lkXG4gICAgICA/IGp3a3Mua2V5cy5maW5kKChrKSA9PiBrLmtpZCA9PT0gaGVhZGVyLmtpZClcbiAgICAgIDogandrcy5rZXlzWzBdO1xuXG4gICAgaWYgKCFqd2spIHtcbiAgICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogZmFsc2UgfTtcbiAgICB9XG5cbiAgICAvLyBWZXJpZnkgc2lnbmF0dXJlIGFuZCBkZWNvZGVcbiAgICBjb25zdCBwYXlsb2FkID0gdmVyaWZ5UlMyNTYodG9rZW4sIGp3ayk7XG4gICAgaWYgKCFwYXlsb2FkKSB7XG4gICAgICByZXR1cm4geyBpc0F1dGhvcml6ZWQ6IGZhbHNlIH07XG4gICAgfVxuXG4gICAgLy8gQ2hlY2sgZXhwaXJhdGlvblxuICAgIGNvbnN0IG5vdyA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDEwMDApO1xuICAgIGlmICh0eXBlb2YgcGF5bG9hZC5leHAgPT09IFwibnVtYmVyXCIgJiYgcGF5bG9hZC5leHAgPCBub3cpIHtcbiAgICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogZmFsc2UgfTtcbiAgICB9XG5cbiAgICAvLyBDaGVjayBpc3N1ZXJcbiAgICBpZiAocGF5bG9hZC5pc3MgIT09IHByb2Nlc3MuZW52Lk9BVVRIX1NFUlZFUl9VUkwpIHtcbiAgICAgIHJldHVybiB7IGlzQXV0aG9yaXplZDogZmFsc2UgfTtcbiAgICB9XG5cbiAgICAvLyBDaGVjayBvcmdfaWQgbWF0Y2hlcyBib3VuZCBvcmdcbiAgICBpZiAocGF5bG9hZC5vcmdfaWQgIT09IHByb2Nlc3MuZW52LkJPVU5EX09SR19JRCkge1xuICAgICAgcmV0dXJuIHsgaXNBdXRob3JpemVkOiBmYWxzZSB9O1xuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICBpc0F1dGhvcml6ZWQ6IHRydWUsXG4gICAgICBjb250ZXh0OiB7XG4gICAgICAgIHVzZXJJZDogU3RyaW5nKHBheWxvYWQuc3ViID8/IFwiXCIpLFxuICAgICAgICBvcmdJZDogU3RyaW5nKHBheWxvYWQub3JnX2lkID8/IFwiXCIpLFxuICAgICAgICBvcmdSb2xlOiBTdHJpbmcocGF5bG9hZC5vcmdfcm9sZSA/PyBcIlwiKSxcbiAgICAgIH0sXG4gICAgfTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIHsgaXNBdXRob3JpemVkOiBmYWxzZSB9O1xuICB9XG59XG4iXX0=