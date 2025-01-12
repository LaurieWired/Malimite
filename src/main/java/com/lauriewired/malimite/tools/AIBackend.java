package com.lauriewired.malimite.tools;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;
import java.util.logging.Level;

import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.ui.AnalysisWindow;
import com.lauriewired.malimite.configuration.Project;
import com.lauriewired.malimite.security.KeyEncryption;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;

public class AIBackend {
    public static class Model {
        private final String displayName;
        private final String provider;
        private final String modelId;

        public Model(String displayName, String provider, String modelId) {
            this.displayName = displayName;
            this.provider = provider;
            this.modelId = modelId;
        }

        public String getDisplayName() { return displayName; }
        public String getProvider() { return provider; }
        public String getModelId() { return modelId; }
    }

    private static final Model[] SUPPORTED_MODELS = {
        new Model("OpenAI GPT-4 Turbo", "openai", "gpt-4-turbo"),
        new Model("OpenAI GPT-4 Mini", "openai", "gpt-4-mini"),
        new Model("Local Model", "local", "local-model")
        
        // TODO: Add support for Claude
        //new Model("Claude", "claude", "claude-v1"),
    };

    public static Model[] getSupportedModels() {
        return SUPPORTED_MODELS;
    }

    public static Model getDefaultModel() {
        return SUPPORTED_MODELS[0]; // Returns GPT-4 Turbo as default
    }

    private static final String OPENAI_API_URL = "https://api.openai.com/v1/chat/completions";
    private static final String CLAUDE_API_URL = "https://api.anthropic.com/v1/complete";

    private static final String DEFAULT_PROMPT = 
        "Translate the following decompiled functions into %s. " +
        "Return only the %s code for these functions, preserving the method names and any global variables. " +
        "You may adjust local variable names for readability, but do not add, remove, or modify any other methods or global definitions. " +
        "Surround each translated function with \"BEGIN_FUNCTION\" at the beginning and \"END_FUNCTION\" at the end. " +
        "Keep functions in the same order as they appear in the original code.";

    private static final String SUMMARIZE_PROMPT =
        "Provide a clear and concise summary of what these functions do. " +
        "Focus on their purpose, key functionality, and any notable patterns. " +
        "If you think this belongs to a known library, mention it. " +
        "Format the response in markdown.\n\n";

    private static final String VULNERABILITY_PROMPT =
        "Analyze these functions for potential security vulnerabilities and coding issues. " +
        "Consider: memory safety, input validation, authentication bypasses, and common coding pitfalls. " +
        "Ignore issues like readability, magic numbers, hardcoded values, and other minor issues since this is decompiled code. " +
        "Don't provide recommendations for fixing these issues, just identify them and say how they could be exploited. " +
        "Format the response in markdown with clear headers for each identified issue.\n\n";

    public static String getPromptForAction(String action, String functionCode) {
        StringBuilder fullPrompt = new StringBuilder();
        
        switch (action) {
            case "Auto Fix":
                Project currentProject = AnalysisWindow.getCurrentProject();
                String targetLanguage = currentProject != null && currentProject.isSwift() ? "Swift" : "Objective-C";
                fullPrompt.append(String.format(DEFAULT_PROMPT, targetLanguage, targetLanguage));
                break;
            case "Summarize":
                fullPrompt.append(SUMMARIZE_PROMPT);
                break;
            case "Find Vulnerabilities":
                fullPrompt.append(VULNERABILITY_PROMPT);
                break;
            default:
                throw new IllegalArgumentException("Unknown action: " + action);
        }

        fullPrompt.append("\nHere are the functions to analyze:\n\n");
        fullPrompt.append(functionCode);
        
        return fullPrompt.toString();
    }

    public static String getDefaultPrompt() {
        Project currentProject = AnalysisWindow.getCurrentProject();
        String targetLanguage = currentProject != null && currentProject.isSwift() ? "Swift" : "Objective-C";
        return String.format(DEFAULT_PROMPT, targetLanguage, targetLanguage);
    }

    public static class ApiKeyMissingException extends Exception {
        public ApiKeyMissingException(String message) {
            super(message);
        }
    }

    private static final Logger LOGGER = Logger.getLogger(AIBackend.class.getName());

    public static String sendToModel(String provider, String modelId, String inputText, Config config) throws IOException, ApiKeyMissingException {
        switch (provider.toLowerCase()) {
            case "openai":
                String openaiKey = KeyEncryption.decrypt(config.getOpenAIApiKey());
                if (openaiKey == null || openaiKey.trim().isEmpty()) {
                    showApiKeyMissingDialog("OpenAI");
                    throw new ApiKeyMissingException("OpenAI API key is missing");
                }
                return sendOpenAIRequest(OPENAI_API_URL, openaiKey, inputText, modelId);

            case "claude":
                String claudeKey = KeyEncryption.decrypt(config.getClaudeApiKey());
                if (claudeKey == null || claudeKey.trim().isEmpty()) {
                    showApiKeyMissingDialog("Claude");
                    throw new ApiKeyMissingException("Claude API key is missing");
                }
                return sendClaudeRequest(CLAUDE_API_URL, claudeKey, inputText, modelId);

            case "local":
                return sendLocalModelRequest(config.getLocalModelUrl(), inputText);

            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
    }

    private static void showApiKeyMissingDialog(String provider) {
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(
                null,
                provider + " API key is not set. Please set it in Preferences.",
                "API Key Missing",
                JOptionPane.WARNING_MESSAGE
            );
        });
    }

    private static String sendOpenAIRequest(String apiUrl, String apiKey, String inputText, String modelId) throws IOException {
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + apiKey);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        // Properly escape the input text for JSON
        String escapedInput = inputText.replace("\\", "\\\\")
                                     .replace("\"", "\\\"")
                                     .replace("\n", "\\n")
                                     .replace("\r", "\\r")
                                     .replace("\t", "\\t")
                                     .replace("\f", "\\f")
                                     .replace("\b", "\\b");

        // Construct the JSON payload using a more structured approach
        String jsonInputString = String.format(
            "{" +
                "\"model\": \"%s\"," +
                "\"messages\": [" +
                    "{" +
                        "\"role\": \"user\"," +
                        "\"content\": \"%s\"" +
                    "}" +
                "]" +
            "}", modelId, escapedInput);

        String response = executeRequest(conn, jsonInputString);
        return parseOpenAIResponse(response);
    }

    private static String parseOpenAIResponse(String jsonResponse) {
        try {
            JSONObject json = new JSONObject(jsonResponse);
            
            // Check for error response
            if (json.has("error")) {
                JSONObject error = json.getJSONObject("error");
                String errorMessage = error.getString("message");
                LOGGER.log(Level.SEVERE, "OpenAI API Error: " + errorMessage);
                return "Error: " + errorMessage;
            }

            // Parse successful response
            JSONArray choices = json.getJSONArray("choices");
            if (choices.length() > 0) {
                JSONObject firstChoice = choices.getJSONObject(0);
                JSONObject message = firstChoice.getJSONObject("message");
                String content = message.getString("content");
                
                // Extract code between triple backticks
                int startIndex = content.indexOf("```");
                if (startIndex != -1) {
                    startIndex = content.indexOf("\n", startIndex) + 1;
                    int endIndex = content.lastIndexOf("```");
                    if (endIndex != -1) {
                        return content.substring(startIndex, endIndex).trim();
                    }
                }
                return content;
            }
            
            // If we get here, something unexpected happened
            LOGGER.log(Level.WARNING, "Unexpected OpenAI response format: " + jsonResponse);
            return "Error: Unexpected response format";
            
        } catch (JSONException e) {
            LOGGER.log(Level.SEVERE, "Error parsing OpenAI response: " + jsonResponse, e);
            return "Error parsing response: " + e.getMessage();
        }
    }

    private static String sendClaudeRequest(String apiUrl, String apiKey, String inputText, String modelId) throws IOException {
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + apiKey);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
    
        // Adjust payload format for Claude API if needed
        String jsonInputString = String.format(
            "{\"model\": \"%s\", \"prompt\": \"%s\"}",
            modelId, inputText
        );
    
        return executeRequest(conn, jsonInputString);
    }    

    private static boolean isChatCompatible(String apiUrl) {
        // Check if the URL contains common chat model endpoints
        return apiUrl.contains("localhost:1234") || // LM Studio
               apiUrl.contains("localhost:5000") || // Text Generation WebUI
               apiUrl.contains("localhost:8080");   // Ollama
    }

    private static String sendLocalModelRequest(String apiUrl, String inputText) throws IOException {
        boolean chatCompatible = isChatCompatible(apiUrl);

        // Use the base URL provided by the user
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String jsonInputString;
        if (chatCompatible) {
            // Use the chat-compatible format
            jsonInputString = String.format(
                "{" +
                    "\"model\": \"local-model\"," +
                    "\"messages\": [{" +
                        "\"role\": \"user\"," +
                        "\"content\": \"%s\"" +
                    "}]," +
                    "\"max_tokens\": 2000," +
                    "\"temperature\": 0.7" +
                "}",
                escapeJsonString(inputText)
            );
        } else {
            // Use the simple completion format
            jsonInputString = String.format(
                "{" +
                    "\"model\": \"local-model\"," +
                    "\"prompt\": \"%s\"," +
                    "\"max_tokens\": 2000," +
                    "\"temperature\": 0.7" +
                "}",
                escapeJsonString(inputText)
            );
        }

        String response = executeRequest(conn, jsonInputString);
        return parseLocalModelResponse(response);
    }

    private static String parseLocalModelResponse(String jsonResponse) {
        try {
            JSONObject json = new JSONObject(jsonResponse);
            
            // Try chat completion format first
            if (json.has("choices")) {
                JSONArray choices = json.getJSONArray("choices");
                if (choices.length() > 0) {
                    JSONObject choice = choices.getJSONObject(0);
                    if (choice.has("message")) {
                        return choice.getJSONObject("message").getString("content");
                    } else if (choice.has("text")) {
                        return choice.getString("text");
                    }
                }
            }
            
            // Fall back to simple completion format
            if (json.has("generated_text")) {
                return json.getString("generated_text");
            }
            
            // If no recognized format is found, return the raw response
            return jsonResponse;
        } catch (JSONException e) {
            LOGGER.log(Level.SEVERE, "Error parsing Local Model response", e);
            return jsonResponse;
        }
    }

    private static String escapeJsonString(String input) {
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t")
                   .replace("\f", "\\f")
                   .replace("\b", "\\b");
    }

    private static String executeRequest(HttpURLConnection conn, String jsonInputString) throws IOException {
        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
    
        int responseCode = conn.getResponseCode();
        InputStream inputStream = (responseCode >= 200 && responseCode < 300) ?
            conn.getInputStream() : conn.getErrorStream();
    
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            return response.toString();
        }
    }    
}

