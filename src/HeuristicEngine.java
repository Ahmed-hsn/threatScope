import java.net.URL;

// ==========================================
// 9. HEURISTIC ENGINE (The Logic)
// ==========================================
class HeuristicEngine {

    // Brands to protect
    private static final String[] PROTECTED_BRANDS = {
            "paypal", "google", "facebook", "amazon", "netflix", "apple", "microsoft",
            "bankofamerica", "coinbase", "binance", "instagram", "whatsapp", "linkedin",
            "dropbox", "adobe", "dhl", "fedex", "usps", "wellsfargo", "chase", "citibank",
            "att", "verizon", "t-mobile", "roblox", "steam", "twitch"
    };

    // Safe Whitelist
    private static final String[] SAFE_DOMAINS = {
            "wikipedia.org", "stackoverflow.com", "github.com", "youtube.com",
            "nytimes.com", "cnn.com", "bbc.com", "medium.com", "reddit.com"
    };

    // Trigger Words
    private static final String[] TRIGGER_WORDS = {
            "login", "signin", "verify", "update", "secure", "account", "banking",
            "confirm", "wallet", "free", "winner", "prize", "urgent", "suspended",
            "unlock", "bonus", "gift", "support", "service", "auth"
    };

    private static final String[] SHORTENERS = {
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "tiny.cc"
    };

    public static ScanResult analyze(String urlStr) {
        ScanResult res = new ScanResult();

        try {
            // Normalize URL
            String originalUrl = urlStr;
            if(!urlStr.startsWith("http")) urlStr = "http://" + urlStr;

            URL url = new URL(urlStr);
            String host = url.getHost().toLowerCase();
            String fullUrl = originalUrl.toLowerCase();

            // --- CHECK 0: WHITELIST ---
            for (String safe : SAFE_DOMAINS) {
                if (host.endsWith(safe)) {
                    res.isThreat = false;
                    res.riskLevel = 0;
                    res.attackModel = "Trusted Domain";
                    res.details = "This domain is in the system's Safe List.";
                    return res;
                }
            }

            // --- CHECK 1: OBFUSCATION (IP Address) ---
            if (host.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
                res.isThreat = true;
                res.riskLevel = 3;
                res.attackModel = "OBFUSCATION (IP Evasion)";
                res.details = "The URL uses a raw IP address (" + host + ") instead of a domain name.";
                return res;
            }

            // --- CHECK 2: OBFUSCATION (Shortener) ---
            for (String s : SHORTENERS) {
                if (host.equals(s)) {
                    res.isThreat = true;
                    res.riskLevel = 2;
                    res.attackModel = "OBFUSCATION (Hidden Destination)";
                    res.details = "This is a shortened URL. The final destination is hidden.";
                    return res;
                }
            }

            // --- CHECK 3: FABRICATION (Brand Spoofing) ---
            for (String brand : PROTECTED_BRANDS) {
                if (fullUrl.contains(brand)) {
                    // Check if it is the OFFICIAL domain
                    boolean isOfficial = host.equals(brand + ".com") ||
                            host.endsWith("." + brand + ".com") ||
                            host.equals(brand + ".net") ||
                            host.endsWith("." + brand + ".net") ||
                            host.equals(brand + ".org");

                    if (!isOfficial) {
                        res.isThreat = true;
                        res.riskLevel = 3; // DANGER
                        res.attackModel = "FABRICATION (Brand Spoofing)";
                        res.details = "The URL contains '" + brand + "' but is hosted on '" + host + "'.\n" +
                                "This is a clone attack.";
                        return res;
                    }
                }
            }

            // --- CHECK 4: STRUCTURAL ANOMALIES ---
            // A. Too many hyphens
            int hyphenCount = host.length() - host.replace("-", "").length();
            if (hyphenCount > 3) {
                res.isThreat = true;
                res.riskLevel = 2;
                res.attackModel = "SUSPICIOUS STRUCTURE (Excessive Hyphens)";
                res.details = "The domain contains " + hyphenCount + " hyphens. Legitimate sites rarely use this many.";
                return res;
            }

            // B. Too many subdomains
            int dotCount = host.length() - host.replace(".", "").length();
            if (dotCount > 4) {
                res.isThreat = true;
                res.riskLevel = 2;
                res.attackModel = "SUSPICIOUS STRUCTURE (Deep Subdomain)";
                res.details = "The URL has " + dotCount + " levels of subdomains.";
                return res;
            }

            // --- CHECK 5: DECEPTION (Social Engineering) ---
            for (String word : TRIGGER_WORDS) {
                if (fullUrl.contains(word)) {
                    res.isThreat = true;
                    res.riskLevel = 2;
                    res.attackModel = "DECEPTION (Social Engineering)";
                    res.details = "The URL uses psychological trigger words ('" + word + "').";
                    return res;
                }
            }

            // --- CHECK 6: INTERCEPTION (HTTP) ---
            if (url.getProtocol().equals("http")) {
                res.isThreat = true;
                res.riskLevel = 2;
                res.attackModel = "INTERCEPTION (Insecure Protocol)";
                res.details = "The site uses HTTP instead of HTTPS.";
                return res;
            }

            // SAFE
            res.isThreat = false;
            res.riskLevel = 0;
            res.attackModel = "None Detected";
            res.details = "The URL structure looks standard. No obvious heuristic threats found.";
            return res;

        } catch (Exception e) {
            res.isThreat = true;
            res.riskLevel = 1;
            res.attackModel = "Invalid Format";
            res.details = "The URL provided is invalid.";
            return res;
        }
    }
}