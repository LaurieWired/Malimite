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
        private String customUrl;

        public Model(String displayName, String provider, String modelId) {
            this.displayName = displayName;
            this.provider = provider;
            this.modelId = modelId;
            this.customUrl = null;
        }

        public Model(String displayName, String provider, String modelId, String customUrl) {
            this(displayName, provider, modelId);
            this.customUrl = customUrl;
        }

        public String getDisplayName() { return displayName; }
        public String getProvider() { return provider; }
        public String getModelId() { return modelId; }
        public String getCustomUrl() { return customUrl; }
        public void setCustomUrl(String url) { this.customUrl = url; }
    }

    private static final Model[] SUPPORTED_MODELS = {
        new Model("OpenAI GPT-4 Turbo", "openai", "gpt-4-turbo"),
        new Model("OpenAI GPT-4 Mini", "openai", "gpt-4-mini"),
        new Model("Custom Model", "custom", "custom")
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

            case "custom":
                Model customModel = findCustomModel();
                if (customModel.getCustomUrl() == null || customModel.getCustomUrl().trim().isEmpty()) {
                    String url = showCustomUrlDialog();
                    if (url == null || url.trim().isEmpty()) {
                        throw new ApiKeyMissingException("Custom URL is required");
                    }
                    customModel.setCustomUrl(url);
                }
                return sendCustomModelRequest(customModel.getCustomUrl(), inputText);

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
        } catch (JSONException e) {
            LOGGER.log(Level.SEVERE, "Error parsing OpenAI response", e);
        }
        return jsonResponse; // Return original response if parsing fails
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

    private static String sendCustomModelRequest(String apiUrl, String inputText) throws IOException {
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        // Use same format as OpenAI for custom endpoints
        String jsonInputString = String.format(
            "{" +
                "\"messages\": [" +
                    "{" +
                        "\"role\": \"user\"," +
                        "\"content\": \"%s\"" +
                    "}" +
                "]" +
            "}", inputText.replace("\"", "\\\""));

        String response = executeRequest(conn, jsonInputString);
        return parseCustomModelResponse(response);
    }

    private static String parseCustomModelResponse(String jsonResponse) {
        try {
            // First try OpenAI format
            return parseOpenAIResponse(jsonResponse);
        } catch (Exception e) {
            // If that fails, return the raw response
            LOGGER.log(Level.INFO, "Could not parse as OpenAI response, returning raw response", e);
            return jsonResponse;
        }
    }

    private static Model findCustomModel() {
        for (Model model : SUPPORTED_MODELS) {
            if ("custom".equals(model.getProvider())) {
                return model;
            }
        }
        throw new IllegalStateException("Custom model not found in SUPPORTED_MODELS");
    }

    private static String showCustomUrlDialog() {
        try {
            final String[] result = new String[1];
            SwingUtilities.invokeAndWait(() -> {
                String url = JOptionPane.showInputDialog(
                    null,
                    "Enter the URL for your custom model API:",
                    "Custom Model Configuration",
                    JOptionPane.PLAIN_MESSAGE
                );
                if (url != null && !url.trim().isEmpty() && !url.startsWith("http")) {
                    url = "http://" + url;
                }
                result[0] = url;
            });
            return result[0];
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error showing custom URL dialog", e);
            return null;
        }
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

