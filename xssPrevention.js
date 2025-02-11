const XSSPrevention = {
    // Combined HTML sanitization function
    sanitizeHTML: (input) => {
        return input
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#x27;")
            .replace(/<(script|iframe|object|embed|form|img|svg|meta|link|style).*?>.*?<\/\1>/gi, "")
            .replace(/<img.*?>/gi, "")
            .replace(/<svg.*?>.*?<\/svg>/gi, "")
            .replace(/<iframe.*?>.*?<\/iframe>/gi, "")
            .replace(/<meta.*?>/gi, "")
            .replace(/<!--.*?-->/g, "")
            .replace(/<!\[CDATA\[.*?\]\]>/gi, "")
            .replace(/<style.*?>.*?<\/style>/gi, "")
            .replace(/<link.*?>/gi, "")
            .replace(/<noscript.*?>.*?<\/noscript>/gi, "")
            .replace(/<base.*?>/gi, "")
            .replace(/on\w+=".*?"/gi, "")
            .replace(/expression\(|javascript:/gi, "");
    },

    // Combined JavaScript sanitization function
    sanitizeJavaScript: (input) => {
        return input
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"')
            .replace(/`/g, "\\`")
            .replace(/\\/g, "\\\\")
            .replace(/\$/g, "\\$")
            .replace(/\(/g, "\\(")
            .replace(/\)/g, "\\)")
            .replace(/\n/g, "\\n")
            .replace(/\r/g, "\\r");
    },

    // Combined URL encoding function
    encodeURL: (input) => {
        return encodeURIComponent(input)
            .replace(/</g, "%3C")
            .replace(/>/g, "%3E")
            .replace(/"/g, "%22")
            .replace(/'/g, "%27");
    },

    // Combined input validation function
    validateInput: (input) => /^[a-zA-Z0-9_ ]*$/.test(input) ? input : "Invalid input",

    // Advanced sanitization function for more specific cases
    advancedSanitize: (input) => {
        return input.replace(/<(script|iframe|object|embed|form|img|svg|meta|link|style).*?>.*?<\/\1>/gi, "")
            .replace(/<script.*?>.*?<\/script>/gi, "")
            .replace(/<iframe.*?>.*?<\/iframe>/gi, "")
            .replace(/<img.*?>/gi, "")
            .replace(/<svg.*?>.*?<\/svg>/gi, "")
            .replace(/<meta.*?>/gi, "")
            .replace(/<!--.*?-->/g, "")
            .replace(/<!\[CDATA\[.*?\]\]>/gi, "")
            .replace(/<style.*?>.*?<\/style>/gi, "")
            .replace(/<link.*?>/gi, "")
            .replace(/<noscript.*?>.*?<\/noscript>/gi, "")
            .replace(/<base.*?>/gi, "");
    }
};

export default XSSPrevention;
