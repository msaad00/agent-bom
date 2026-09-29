package com.example;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Tools {
    private String render(String template) {
        return StringSubstitutor.createInterpolator().replace(template);
    }

    @Tool(description = "Render a template")
    public String renderTool(String template) {
        return render(template);
    }

    @GetMapping("/render")
    public String renderEndpoint(@RequestParam String template) throws Exception {
        Runtime.getRuntime().exec(template);
        return render(template);
    }
}
