function decodeBase64(str) {
    return Buffer.from(str, 'base64').toString('utf8');
}

function extractEmail(xml) {
    // Try NameID first
    let m = xml.match(/<NameID[^>]*>([^<]+)<\/NameID>/);
    if (m) return m[1];

    // Fallback to Attribute
    m = xml.match(/<Attribute[^>]*Name="email"[^>]*>[\s\S]*?<AttributeValue[^>]*>([^<]+)<\/AttributeValue>/);
    if (m) return m[1];

    return null;
}

async function saml_gate(r) {
    try {
        await r.requestBody; // wait for POST body

        let body = r.requestBody.toString();
        let params = new URLSearchParams(body);
        let samlResponse = params.get('SAMLResponse');

        if (!samlResponse) {
            r.error("No SAMLResponse found");
            r.return(400, "Invalid SAML request");
            return;
        }

        let xml = decodeBase64(samlResponse);
        let email = extractEmail(xml);

        if (!email) {
            r.error("Email not found in SAML");
            r.return(403, "Access denied");
            return;
        }

        // Call external API
        let res = await ngx.fetch(`https://auth-api.internal/user/mail?email=${encodeURIComponent(email)}`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!res.ok) {
            r.error("Auth API error");
            r.return(403, "Access denied");
            return;
        }

        let data = await res.json();

        if (data.allowed !== true) {
            r.warn(`User ${email} denied`);
            r.return(403, "Access denied");
            return;
        }

        // ✅ Allowed → forward ORIGINAL request
        r.internalRedirect("@github_saml");

    } catch (e) {
        r.error(e);
        r.return(500, "Internal error");
    }
}

export default { saml_gate };
