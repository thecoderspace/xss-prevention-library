const XSSPrevention = {
    sanitizeHTML: (input) => input.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;"),
    
    sanitizeJavaScript: (input) => input.replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/`/g, "\\`"),
    
    sanitizeHTMLAttributes: (input) => input.replace(/"/g, "&quot;").replace(/'/g, "&#x27;"),
    
    sanitizeJavaAttributes: (input) => input.replace(/"/g, "\\\"").replace(/'/g, "\\'"),
    
    encodeURL: (input) => encodeURIComponent(input),
    
    sanitizeASCII: (input) => input.replace(/&/g, "&#38;").replace(/</g, "&#60;").replace(/>/g, "&#62;").replace(/'/g, "&#39;").replace(/"/g, "&#34;"),
    
    escapeJavaScriptString: (input) => input.replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/"/g, "\\\"").replace(/\n/g, "\\n").replace(/\r/g, "\\r"),
    
    escapeJavaString: (input) => input.replace(/\\/g, "\\\\").replace(/"/g, "\\\"").replace(/'/g, "\\'").replace(/\n/g, "\\n").replace(/\r/g, "\\r"),
    
    removeScriptTags: (input) => input.replace(/<script.*?>.*?<\/script>/gi, ""),
    
    advancedSanitize: (input) => input.replace(/<(script|iframe|object|embed|form).*?>.*?<\/\1>/gi, ""),
    
    escapeJSON: (input) => input.replace(/"/g, "\\\"").replace(/</g, "\\u003C").replace(/>/g, "\\u003E"),
    
    validateInput: (input) => /^[a-zA-Z0-9_ ]*$/.test(input) ? input : "Invalid input",
    
    encodeASCIIURL: (url) => url.replace(/</g, "%3C").replace(/>/g, "%3E").replace(/"/g, "%22").replace(/'/g, "%27"),
    
    removeEventHandlers: (input) => input.replace(/on\w+=".*?"/gi, ""),
    
    sanitizeCSS: (input) => input.replace(/expression\(|javascript:/gi, "")
};

export default XSSPrevention;
