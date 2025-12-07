import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.*;


public class ThreatScope extends JFrame {

    // --- 1. VISUAL THEME (Colors & Fonts) ---
    private static final Color COLOR_BG = new Color(18, 20, 28);       // Dark Background
    private static final Color COLOR_PANEL = new Color(30, 34, 46);    // Lighter Panels
    private static final Color COLOR_ACCENT = new Color(0, 210, 255);  // Cyan Blue
    private static final Color COLOR_SAFE = new Color(46, 204, 113);   // Green
    private static final Color COLOR_DANGER = new Color(231, 76, 60);  // Red
    private static final Color COLOR_WARN = new Color(241, 196, 15);   // Yellow

    private static final Font FONT_HEADER = new Font("Segoe UI", Font.BOLD, 22);
    private static final Font FONT_TEXT = new Font("Consolas", Font.PLAIN, 13);

    // --- 2. GUI COMPONENTS ---
    private JTextField urlInputField;
    private JTextArea reportArea;
    private JLabel statusLabel;
    private JPanel statusPanel;
    private ModernButton scanButton;

    // --- 3. MAIN SETUP ---
    public ThreatScope() {
        setTitle("ThreatScope - Advanced Phishing Detector");
        setSize(900, 650);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center on screen
        setLayout(new BorderLayout());
        getContentPane().setBackground(COLOR_BG);

        initUI(); // Build the visual interface
    }

    // --- 4. UI BUILDER ---
    private void initUI() {
        // A. Header Section
        JPanel header = new JPanel();
        header.setBackground(COLOR_BG);
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBorder(new EmptyBorder(30, 0, 20, 0));

        JLabel title = new JLabel("THREAT SCOPE");
        title.setFont(FONT_HEADER);
        title.setForeground(COLOR_ACCENT);
        title.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subtitle = new JLabel("Phishing Detection & Attack Model Analysis");
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        subtitle.setForeground(Color.GRAY);
        subtitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        header.add(title);
        header.add(Box.createVerticalStrut(5));
        header.add(subtitle);

        // B. Input Section
        JPanel inputPanel = new RoundedPanel(20, COLOR_PANEL);
        inputPanel.setLayout(new BorderLayout(15, 0));
        inputPanel.setBorder(new EmptyBorder(10, 20, 10, 20));
        inputPanel.setMaximumSize(new Dimension(800, 60));

        urlInputField = new JTextField("http://");
        urlInputField.setBackground(COLOR_PANEL);
        urlInputField.setForeground(Color.WHITE);
        urlInputField.setCaretColor(COLOR_ACCENT);
        urlInputField.setBorder(null);
        urlInputField.setFont(new Font("Consolas", Font.PLAIN, 14));

        scanButton = new ModernButton("SCAN URL");
        scanButton.addActionListener(e -> startScanProcess());

        inputPanel.add(new JLabel("🔗") {{ setForeground(Color.GRAY); setFont(new Font("Segoe UI Emoji", Font.PLAIN, 20)); }}, BorderLayout.WEST);
        inputPanel.add(urlInputField, BorderLayout.CENTER);
        inputPanel.add(scanButton, BorderLayout.EAST);

        // C. Dashboard Section (Results)
        JPanel dashboard = new JPanel();
        dashboard.setLayout(new BoxLayout(dashboard, BoxLayout.Y_AXIS));
        dashboard.setBackground(COLOR_BG);
        dashboard.setBorder(new EmptyBorder(20, 50, 20, 50));

        // Status Box
        statusPanel = new RoundedPanel(20, COLOR_PANEL);
        statusPanel.setMaximumSize(new Dimension(800, 80));
        statusPanel.setLayout(new GridBagLayout());

        statusLabel = new JLabel("READY TO SCAN");
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        statusLabel.setForeground(Color.GRAY);
        statusPanel.add(statusLabel);

        // Report Text Area
        reportArea = new JTextArea();
        reportArea.setEditable(false);
        reportArea.setFont(FONT_TEXT);
        reportArea.setBackground(new Color(24, 26, 32));
        reportArea.setForeground(new Color(200, 200, 200));
        reportArea.setBorder(new EmptyBorder(15, 15, 15, 15));
        reportArea.setLineWrap(true);
        reportArea.setWrapStyleWord(true);

        JScrollPane scroll = new JScrollPane(reportArea);
        scroll.setBorder(BorderFactory.createLineBorder(COLOR_PANEL, 1));
        scroll.setPreferredSize(new Dimension(800, 250));

        dashboard.add(inputPanel);
        dashboard.add(Box.createVerticalStrut(30));
        dashboard.add(statusPanel);
        dashboard.add(Box.createVerticalStrut(20));
        dashboard.add(scroll);

        add(header, BorderLayout.NORTH);
        add(dashboard, BorderLayout.CENTER);
    }

    // --- 5. LOGIC CONTROLLER ---

    private void startScanProcess() {
        String url = urlInputField.getText().trim();

        if (url.isEmpty() || url.equals("http://")) {
            JOptionPane.showMessageDialog(this, "Please enter a valid URL.");
            return;
        }

        // Update UI to Loading State
        statusLabel.setText("SCANNING...");
        statusLabel.setForeground(COLOR_ACCENT);
        reportArea.setText("1. Connecting to VirusTotal API...\n2. Analyzing URL Structure...\n3. Checking Brand Spoofing...");
        scanButton.setEnabled(false);

        // Run in Background Thread
        new Thread(() -> {
            ScanResult result = performAnalysis(url);

            // Update UI when done
            SwingUtilities.invokeLater(() -> {
                displayResults(result);
                scanButton.setEnabled(true);
            });
        }).start();
    }

    // The "Brain" of the application
    private ScanResult performAnalysis(String urlStr) {
        ScanResult result = new ScanResult();

        // Step 1: Check VirusTotal API (The Blacklist)
        boolean isConfirmedPhish = VirusTotalClient.checkUrl(urlStr);

        if (isConfirmedPhish) {
            result.isThreat = true;
            result.attackModel = "BLACKLISTED (Confirmed Threat)";
            result.details = "This URL is flagged as malicious by security engines on VirusTotal.\n" +
                    "Do not visit this link.";
            result.riskLevel = 3; // High Danger
            return result;
        }

        // Step 2: Run Heuristic Analysis (The Logic)
        // If API says it's clean (or unknown), we check it ourselves.
        return HeuristicEngine.analyze(urlStr);
    }

    // Display final report
    private void displayResults(ScanResult res) {
        reportArea.setText("");

        if (res.riskLevel == 3) {
            statusLabel.setText("⚠️ PHISHING DETECTED");
            statusLabel.setForeground(COLOR_DANGER);
            ((RoundedPanel)statusPanel).borderColor = COLOR_DANGER;
        } else if (res.riskLevel == 2) {
            statusLabel.setText("⚠️ SUSPICIOUS URL");
            statusLabel.setForeground(COLOR_WARN);
            ((RoundedPanel)statusPanel).borderColor = COLOR_WARN;
        } else {
            statusLabel.setText("✅ URL SEEMS SAFE");
            statusLabel.setForeground(COLOR_SAFE);
            ((RoundedPanel)statusPanel).borderColor = COLOR_SAFE;
        }
        statusPanel.repaint();

        reportArea.append("ATTACK MODEL: " + res.attackModel + "\n");
        reportArea.append("--------------------------------------------------\n");
        reportArea.append(res.details + "\n");

        if(res.riskLevel == 0) {
            reportArea.append("\nNote: No obvious threats found, but always verify the source.");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ThreatScope().setVisible(true));
    }

    // --- 6. CUSTOM UI CLASSES ---

    static class RoundedPanel extends JPanel {
        private int radius;
        private Color bgColor;
        public Color borderColor = null;

        public RoundedPanel(int radius, Color bgColor) {
            this.radius = radius;
            this.bgColor = bgColor;
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(bgColor);
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);

            if(borderColor != null) {
                g2.setColor(borderColor);
                g2.setStroke(new BasicStroke(2));
                g2.drawRoundRect(1, 1, getWidth()-2, getHeight()-2, radius, radius);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }

    static class ModernButton extends JButton {
        public ModernButton(String text) {
            super(text);
            setContentAreaFilled(false);
            setFocusPainted(false);
            setBorderPainted(false);
            setForeground(Color.BLACK);
            setFont(new Font("Segoe UI", Font.BOLD, 14));
            setCursor(new Cursor(Cursor.HAND_CURSOR));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            if (getModel().isPressed()) g2.setColor(COLOR_ACCENT.darker());
            else if (getModel().isRollover()) g2.setColor(COLOR_ACCENT.brighter());
            else g2.setColor(COLOR_ACCENT);
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 15, 15);
            super.paintComponent(g);
            g2.dispose();
        }
    }
}
