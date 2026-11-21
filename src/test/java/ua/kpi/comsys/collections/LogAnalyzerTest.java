package ua.kpi.comsys.collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogAnalyzerTest {

    private LogAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new LogAnalyzer();
    }

    @Test
    void shouldReturnUniqueIpsFromValidLogLines() {
        List<String> logs = List.of(
                "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET /index.html HTTP/1.1\" 200 9481",
                "192.168.1.10 - - [01/May/2025:07:21:15 +0000] \"POST /api/login HTTP/1.1\" 401 512",
                "127.0.0.1 - bob [01/May/2025:07:22:00 +0000] \"GET /dashboard HTTP/1.1\" 200 -"
        );

        Set<String> result = analyzer.getUniqueIps(logs);

        assertEquals(Set.of("127.0.0.1", "192.168.1.10"), result);
    }

    @Test
    void shouldIgnoreMalformedAndNullLinesInGetUniqueIps() {
        List<String> logs = Arrays.asList(
                null,
                "",
                "   ",
                "invalid log entry",
                "999.999.1.1 - - [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 100",
                "10.0.0.1 - - 2025-05-01 \"GET / HTTP/1.1\" 200 100",
                "10.0.0.2 - - [01/May/2025:07:25:00 +0200] \"DELETE /item/1 HTTP/1.1\" 204 0"
        );

        Set<String> result = analyzer.getUniqueIps(logs);

        assertEquals(Set.of("10.0.0.2"), result);
    }

    @Test
    void shouldReturnEmptySetWhenLogsAreEmpty() {
        assertTrue(analyzer.getUniqueIps(Collections.emptyList()).isEmpty());
    }

    @Test
    void shouldThrowExceptionWhenGetUniqueIpsReceivesNull() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getUniqueIps(null)
        );
        assertEquals("logLines cannot be null", ex.getMessage());
    }

    @Test
    void shouldReturnTopIpsSortedByFrequencyDescending() {
        List<String> logs = List.of(
                "10.0.0.1 - - [01/May/2025:07:20:10 +0000] \"GET /a HTTP/1.1\" 200 100",
                "10.0.0.2 - - [01/May/2025:07:20:11 +0000] \"GET /a HTTP/1.1\" 200 100",
                "10.0.0.2 - - [01/May/2025:07:20:12 +0000] \"GET /b HTTP/1.1\" 200 100",
                "10.0.0.3 - - [01/May/2025:07:20:13 +0000] \"GET /a HTTP/1.1\" 200 100",
                "10.0.0.3 - - [01/May/2025:07:20:14 +0000] \"GET /b HTTP/1.1\" 200 100",
                "10.0.0.3 - - [01/May/2025:07:20:15 +0000] \"GET /c HTTP/1.1\" 200 100"
        );

        List<String> top2 = analyzer.getTopIps(logs, 2);

        assertEquals(List.of("10.0.0.3", "10.0.0.2"), top2);
    }

    @Test
    void shouldBreakTiesLexicographicallyAscending() {
        List<String> logs = List.of(
                "192.168.0.20 - - [01/May/2025:07:20:10 +0000] \"GET /a HTTP/1.1\" 200 100",
                "192.168.0.10 - - [01/May/2025:07:20:11 +0000] \"GET /a HTTP/1.1\" 200 100",
                "10.0.0.5 - - [01/May/2025:07:20:12 +0000] \"GET /a HTTP/1.1\" 200 100",
                "192.168.0.20 - - [01/May/2025:07:20:13 +0000] \"GET /b HTTP/1.1\" 200 100",
                "192.168.0.10 - - [01/May/2025:07:20:14 +0000] \"GET /b HTTP/1.1\" 200 100",
                "10.0.0.5 - - [01/May/2025:07:20:15 +0000] \"GET /b HTTP/1.1\" 200 100"
        );

        List<String> top2 = analyzer.getTopIps(logs, 2);

        assertEquals(List.of("10.0.0.5", "192.168.0.10"), top2);
    }

    @Test
    void shouldReturnAllAvailableIpsWhenUniqueCountIsLessThanTopN() {
        List<String> logs = List.of(
                "172.16.0.2 - - [01/May/2025:07:20:10 +0000] \"GET /a HTTP/1.1\" 200 100",
                "172.16.0.1 - - [01/May/2025:07:20:11 +0000] \"GET /a HTTP/1.1\" 200 100"
        );

        List<String> result = analyzer.getTopIps(logs, 10);

        assertEquals(List.of("172.16.0.1", "172.16.0.2"), result);
    }

    @Test
    void shouldThrowExceptionWhenGetTopIpsReceivesNullLogs() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(null, 3)
        );
        assertEquals("logLines cannot be null", ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, -100})
    void shouldThrowExceptionWhenTopNIsNotPositive(int invalidTopN) {
        List<String> logs = List.of(
                "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET /index.html HTTP/1.1\" 200 9481"
        );

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(logs, invalidTopN)
        );
        assertEquals("topN must be greater than 0", ex.getMessage());
    }
}