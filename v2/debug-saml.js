function decodeBase64(str) {
    return Buffer.from(str, 'base64').toString('utf8');
}

function extractEmail(xml) {
    // Try NameID first
    let m = xml.match(/<NameID[^>]*>([^<]+)<\/NameID>/);
    if (m) return m[1];

    // Try email attribute
    m = xml.match(/<Attribute[^>]*Name="email"[^>]*>[\s\S]*?<AttributeValue[^>]*>([^<]+)<\/AttributeValue>/);
    if (m) return m[1];

    return null;
}

async function saml_gate(r) {
    try {
        // Wait until POST body is fully read
        await r.requestBody;

        let body = r.requestBody.toString();
        let params = new URLSearchParams(body);
        let samlResponse = params.get('SAMLResponse');

        if (!samlResponse) {
            r.error("[SAML DEBUG] No SAMLResponse found");
            r.return(400, "Invalid SAML request");
            return;
        }

        let xml = decodeBase64(samlResponse);
        let email = extractEmail(xml);

        if (!email) {
            r.warn("[SAML DEBUG] Email NOT found in SAML assertion");
        } else {
            // 👇 This is what you want to see
            r.notice(`[SAML DEBUG] Auth attempt from email: ${email}`);
        }

        // ✅ Always allow auth in debug mode
        r.internalRedirect("@github_saml");

    } catch (e) {
        r.error(`[SAML DEBUG] Exception: ${e}`);
        r.return(500, "Internal error");
    }
}

export default { saml_gate };
