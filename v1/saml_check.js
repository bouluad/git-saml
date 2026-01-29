async function validateUser(r) {
    try {
        // 1. Get the body (ensure client_body_buffer_size is large enough)
        let body = r.requestText;
        
        // 2. Extract SAMLResponse from the Form Data
        let params = new URLSearchParams(body);
        let samlEncoded = params.get('SAMLResponse');

        if (!samlEncoded) {
            r.return(400, "Missing SAMLResponse");
            return;
        }

        // 3. Decode Base64 (njs built-in)
        let decoded = Buffer.from(samlEncoded, 'base64').toString();

        // 4. Extract Email (Adjust regex based on your IdP's XML structure)
        // Usually looking for NameID or an AttributeStatement
        let emailMatch = decoded.match(/<saml2:NameID.*?>(.*?)<\/saml2:NameID>/) 
                      || decoded.match(/Attribute Name="email".*?<saml2:AttributeValue.*?>(.*?)<\/saml2:AttributeValue>/);
        
        if (!emailMatch) {
            r.return(403, "Email not found in SAML assertion");
            return;
        }

        let userEmail = emailMatch[1];

        // 5. Call External API
        let res = await r.subrequest('/_validate_email', {
            method: 'GET',
            args: 'email=' + encodeURIComponent(userEmail)
        });

        if (res.status === 200) {
            // Success: Internal redirect to the actual GitHub location
            r.internalRedirect('/_github_upstream');
        } else {
            r.return(403, "Access Denied: User not authorized in external API");
        }

    } catch (e) {
        r.return(500, "Internal Server Error during SAML check");
    }
}

export default { validateUser };
