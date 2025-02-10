const XSSPrevention = {
    sanitizeHTML: (input) => input.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;").replace(/&/g, "&amp;"),
    
    sanitizeJavaScript: (input) => input
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/`/g, "\\`")
        .replace(/\/g, "\\\\")
        .replace(/\$/g, "\\$")
        .replace(/\(/g, "\\(")
        .replace(/\)/g, "\\)"),
    
    sanitizeHTMLAttributes: (input) => input.replace(/"/g, "&quot;").replace(/'/g, "&#x27;"),
    
    sanitizeJavaAttributes: (input) => input.replace(/"/g, "\\\"").replace(/'/g, "\\'"),
    
    encodeURL: (input) => encodeURIComponent(input),
    
    sanitizeASCII: (input) => input
        .replace(/&/g, "&#38;")
        .replace(/</g, "&#60;")
        .replace(/>/g, "&#62;")
        .replace(/'/g, "&#39;")
        .replace(/"/g, "&#34;")
        .replace(/`/g, "&#96;")
        .replace(/\/g, "&#92;"),
    
    escapeJavaScriptString: (input) => input
        .replace(/\\/g, "\\\\")
        .replace(/'/g, "\\'")
        .replace(/"/g, "\\\"")
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r"),
    
    escapeJavaString: (input) => input
        .replace(/\\/g, "\\\\")
        .replace(/"/g, "\\\"")
        .replace(/'/g, "\\'")
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r"),
    
    removeScriptTags: (input) => input.replace(/<script.*?>.*?<\/script>/gi, ""),
    
    removeImageTags: (input) => input.replace(/<img.*?>/gi, ""),
    
    removeSVGTags: (input) => input.replace(/<svg.*?>.*?<\/svg>/gi, ""),
    
    removeIframeTags: (input) => input.replace(/<iframe.*?>.*?<\/iframe>/gi, ""),
    
    removeMetaTags: (input) => input.replace(/<meta.*?>/gi, ""),
    
    advancedSanitize: (input) => input.replace(/<(script|iframe|object|embed|form|img|svg|meta|link|style).*?>.*?<\/\1>/gi, ""),
    
    escapeJSON: (input) => input
        .replace(/"/g, "\\\"")
        .replace(/</g, "\\u003C")
        .replace(/>/g, "\\u003E")
        .replace(/'/g, "\\u0027"),
    
    validateInput: (input) => /^[a-zA-Z0-9_ ]*$/.test(input) ? input : "Invalid input",
    
    encodeASCIIURL: (url) => url.replace(/</g, "%3C").replace(/>/g, "%3E").replace(/"/g, "%22").replace(/'/g, "%27"),
    
    removeEventHandlers: (input) => input.replace(/on\w+=\".*?\"/gi, ""),
    
    sanitizeCSS: (input) => input.replace(/expression\(|javascript:/gi, ""),
    
    sanitizeAdvancedASCII: (input) => input
        .replace(/[\u0080-\uFFFF]/g, (char) => `&#${char.charCodeAt(0)};`),
    
    removeCommentTags: (input) => input.replace(/<!--.*?-->/g, ""),
    
    sanitizeJSONKeys: (input) => input.replace(/[^a-zA-Z0-9_]/g, ""),
    
    removeCDATASections: (input) => input.replace(/<!\[CDATA\[.*?\]\]>/gi, ""),
    
    removeStyleTags: (input) => input.replace(/<style.*?>.*?<\/style>/gi, ""),
    
    removeLinkTags: (input) => input.replace(/<link.*?>/gi, ""),
    
    removeNoscriptTags: (input) => input.replace(/<noscript.*?>.*?<\/noscript>/gi, ""),
    
    neutralizeBaseHref: (input) => input.replace(/<base.*?>/gi, ""),
    
    stripHexEncoding: (input) => input.replace(/%[0-9A-F]{2}/gi, ""),
};

export default XSSPrevention;
