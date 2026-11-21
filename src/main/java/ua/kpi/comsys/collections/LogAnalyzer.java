package ua.kpi.comsys.collections;

import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogAnalyzer {

    private static final String IPV4_PART = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
    private static final String IPV4_REGEX = "(?:" + IPV4_PART + "\\.){3}" + IPV4_PART;
    private static final String IPV6_REGEX = "[0-9a-fA-F:]+:[0-9a-fA-F:]+";

    private static final Pattern CLF_PATTERN = Pattern.compile(
            "^(" + IPV4_REGEX + "|" + IPV6_REGEX + ")\\s+" +
                    "\\S+\\s+" +
                    "\\S+\\s+" +
                    "\\[\\d{2}/[A-Za-z]{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2}\\s+[+-]\\d{4}\\]\\s+" +
                    "\"[^\"]+\"\\s+" +
                    "\\d{3}\\s+" +
                    "(?:\\d+|-)$"
    );

    public Set<String> getUniqueIps(List<String> logLines) {
        if (logLines == null) {
            throw new IllegalArgumentException("logLines cannot be null");
        }

        Set<String> uniqueIps = new HashSet<>();
        for (String line : logLines) {
            String ip = extractValidIp(line);
            if (ip != null) {
                uniqueIps.add(ip);
            }
        }
        return uniqueIps;
    }

    public List<String> getTopIps(List<String> logLines, int topN) {
        if (logLines == null) {
            throw new IllegalArgumentException("logLines cannot be null");
        }
        if (topN <= 0) {
            throw new IllegalArgumentException("topN must be greater than 0");
        }

        Map<String, Integer> frequencyMap = new HashMap<>();
        for (String line : logLines) {
            String ip = extractValidIp(line);
            if (ip != null) {
                frequencyMap.merge(ip, 1, Integer::sum);
            }
        }

        return frequencyMap.entrySet().stream()
                .sorted(Comparator
                        .comparingInt(Map.Entry<String, Integer>::getValue).reversed()
                        .thenComparing(Map.Entry::getKey))
                .limit(topN)
                .map(Map.Entry::getKey)
                .toList();
    }

    private String extractValidIp(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        Matcher matcher = CLF_PATTERN.matcher(line.trim());
        return matcher.matches() ? matcher.group(1) : null;
    }
}