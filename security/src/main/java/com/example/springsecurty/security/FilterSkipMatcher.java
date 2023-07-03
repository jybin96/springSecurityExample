package com.example.springsecurty.security;

import java.util.List;
import java.util.stream.Collectors;
import javafx.util.Pair;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class FilterSkipMatcher implements RequestMatcher {
    private final OrRequestMatcher orRequestMatcher;
    private final RequestMatcher processingMatcher;

    public FilterSkipMatcher(List<Pair<HttpMethod, String>> pathToSkips, String processingPath){
        this.orRequestMatcher = new OrRequestMatcher(pathToSkips
                .stream()
                .map(this::httpPath)
                .collect(Collectors.toList()));

        this.processingMatcher = new AntPathRequestMatcher(processingPath);
    }

    AntPathRequestMatcher httpPath(Pair<HttpMethod, String> pathToSkip){
        return new AntPathRequestMatcher(pathToSkip.getValue(), pathToSkip.getKey().toString());
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return !orRequestMatcher.matches(request) && processingMatcher.matches(request);
    }
}
