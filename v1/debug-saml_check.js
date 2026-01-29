function validateUser(r) {
    // 1. Ensure we have a body
    let body = r.requestText;
    if (!body) {
        r.error("SAML Debug: No request body found. Check client_body_buffer_size.");
        r.internalRedirect('/_github_upstream');
        return;
    }

    // 2. Extract SAMLResponse
    let params = new URLSearchParams(body);
    let samlEncoded = params.get('SAMLResponse');

    if (!samlEncoded) {
        r.error("SAML Debug: SAMLResponse parameter missing in POST body");
        r.internalRedirect('/_github_upstream');
        return;
    }

    // 3. Decode Base64
    let decoded = Buffer.from(samlEncoded, 'base64').toString();

    // 4. Extract Email using a broad Regex
    // This looks for common NameID formats or Attribute values
    let emailMatch = decoded.match(/<saml2:NameID.*?>(.*?)<\/saml2:NameID>/) 
                  || decoded.match(/<saml:NameID.*?>(.*?)<\/saml:NameID>/)
                  || decoded.match(/AttributeValue.*?>(.*?)<\/.*?AttributeValue>/);
    
    let userEmail = emailMatch ? emailMatch[1] : "NOT_FOUND";

    // 5. Log the result to Nginx Error Log (at 'info' or 'error' level)
    r.error("SAML Debug: Found User Email -> " + userEmail);

    // 6. Authorize and Pass Through
    r.internalRedirect('/_github_upstream');
}

export default { validateUser };
