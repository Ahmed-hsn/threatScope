import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// ==========================================
// 8. VIRUSTOTAL API CLIENT
// ==========================================
class VirusTotalClient {

    // Your API Key
    private static final String API_KEY = "API_KEY";

    public static boolean checkUrl(String urlToCheck) {
        try {
            // 1. Encode URL to Base64 (Required by VirusTotal)
            String urlId = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(urlToCheck.getBytes(StandardCharsets.UTF_8));

            // 2. Build API Request
            URL url = new URL("https://www.virustotal.com/api/v3/urls/" + urlId);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // 3. Set Headers
            conn.setRequestMethod("GET");
            conn.setRequestProperty("x-apikey", API_KEY);
            conn.setRequestProperty("Accept", "application/json");

            // 4. Check Response Code
            int responseCode = conn.getResponseCode();
            if (responseCode == 404) {
                // 404 means VirusTotal hasn't seen this URL before. Assume safe for now.
                return false;
            } else if (responseCode != 200) {
                System.out.println("API Error: " + responseCode);
                return false;
            }

            // 5. Read Response
            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }

            String json = response.toString();

            // 6. Parse JSON to find "malicious" count
            // We look for the string: "malicious": X
            int maliciousIndex = json.indexOf("\"malicious\":");
            if (maliciousIndex != -1) {
                String temp = json.substring(maliciousIndex + 12); // Skip "malicious":
                int commaIndex = temp.indexOf(",");
                if (commaIndex != -1) {
                    String countStr = temp.substring(0, commaIndex).trim();
                    int maliciousCount = Integer.parseInt(countStr);

                    if (maliciousCount > 0) {
                        System.out.println("VirusTotal found " + maliciousCount + " engines flagging this URL.");
                        return true; // It is a threat!
                    }
                }
            }

            return false; // 0 engines flagged it

        } catch (Exception e) {
            System.out.println("VirusTotal Check Failed: " + e.getMessage());
            return false;
        }
    }
}
